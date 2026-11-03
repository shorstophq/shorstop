package main

import (
	"cmp"
	"fmt"
	"io"
	"slices"
	"text/tabwriter"

	"github.com/spf13/cobra"

	"github.com/shorstophq/shorstop/internal/detect/cert"
	"github.com/shorstophq/shorstop/internal/detect/config"
	"github.com/shorstophq/shorstop/internal/rules"
)

func newRulesCmd(stdout io.Writer) *cobra.Command {
	rulesCmd := &cobra.Command{
		Use:   "rules",
		Short: "Show the rules ShorStop checks",
		Args:  cobra.NoArgs,
	}
	var detector string
	var files stringList
	list := &cobra.Command{
		Use:   "list",
		Short: "List every rule: the rule pack and the built-in certificate and configuration rules",
		Args:  cobra.NoArgs,
		RunE: func(*cobra.Command, []string) error {
			pack, _, err := loadRules(files, nil)
			if err != nil {
				return err
			}
			return listRules(stdout, pack, detector)
		},
	}
	list.Flags().StringVar(&detector, "detector", "", "only rules of this detector (goast, regex, deps, cert, config)")
	list.Flags().Var(&files, "rules", "also list the rules of this rule file, checking it (repeatable)")
	rulesCmd.AddCommand(list)
	return rulesCmd
}

// ruleRow is one line of `rules list`.
type ruleRow struct{ id, detector, algorithm, description string }

func listRules(w io.Writer, pack *rules.Pack, detector string) error {
	var rows []ruleRow
	for _, r := range pack.Rules {
		rows = append(rows, ruleRow{r.ID, r.Detector, cmp.Or(r.Algorithm, "-"), r.Description})
	}
	for name, descs := range map[string]map[string]string{cert.Name: cert.RuleDescriptions, config.Name: config.RuleDescriptions} {
		for id, d := range descs {
			rows = append(rows, ruleRow{id, name, "-", d})
		}
	}
	if detector != "" {
		rows = slices.DeleteFunc(rows, func(r ruleRow) bool { return r.detector != detector })
		if len(rows) == 0 {
			return fmt.Errorf("no rules for detector %q (detectors: cert, config, deps, goast, regex)", detector)
		}
	}
	slices.SortFunc(rows, func(a, b ruleRow) int { return cmp.Compare(a.id, b.id) })

	tw := tabwriter.NewWriter(w, 0, 0, 2, ' ', 0)
	fmt.Fprintln(tw, "ID\tDETECTOR\tALGORITHM\tDESCRIPTION")
	for _, r := range rows {
		fmt.Fprintf(tw, "%s\t%s\t%s\t%s\n", r.id, r.detector, r.algorithm, r.description)
	}
	if err := tw.Flush(); err != nil {
		return err
	}
	_, err := fmt.Fprintf(w, "%d rules\n", len(rows))
	return err
}
