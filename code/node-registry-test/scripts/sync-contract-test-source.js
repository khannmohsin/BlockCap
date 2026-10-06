#!/usr/bin/env node
"use strict";

// The contract test harness deliberately has no independently maintained
// Solidity source.  Materialize its input from the deployment authority right
// before compilation, and fail if the expected NodeRegistry source is absent.
const fs = require("fs");
const path = require("path");

const projectRoot = path.resolve(__dirname, "..");
const sourceDir = path.resolve(projectRoot, "../Node_root/smart_contract_deployment/contracts");
const targetDir = path.join(projectRoot, "contracts");
const registry = path.join(sourceDir, "NodeRegistry.sol");

if (!fs.existsSync(registry)) {
  throw new Error(`Authoritative contract source is missing: ${registry}`);
}
fs.mkdirSync(targetDir, { recursive: true });
for (const name of fs.readdirSync(sourceDir)) {
  if (!name.endsWith(".sol")) continue;
  fs.copyFileSync(path.join(sourceDir, name), path.join(targetDir, name));
}
console.log(`Synced Solidity test input from ${sourceDir}`);
