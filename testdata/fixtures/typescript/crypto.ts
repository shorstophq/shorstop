// Fixture: .ts files get the JavaScript rules.
import { generateKeyPairSync, createHash } from "node:crypto";

const pair = generateKeyPairSync("x25519");
const digest: string = createHash("sha1").update(input).digest("hex");
