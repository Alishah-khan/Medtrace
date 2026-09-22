// Compiles MedTrace.sol with solc-js and deploys it to a JSON-RPC node.
// Local:   npx hardhat node   (terminal 1)  then  node deploy.js  (terminal 2)
// Testnet: set RPC_URL and PRIVATE_KEY environment variables first.
const fs = require("fs");
const path = require("path");
const solc = require("solc");
const { ethers } = require("ethers");

async function main() {
  const src = fs.readFileSync(path.join(__dirname, "MedTrace.sol"), "utf8");
  const input = {
    language: "Solidity",
    sources: { "MedTrace.sol": { content: src } },
    settings: {
      evmVersion: "paris",
      optimizer: { enabled: true, runs: 200 },
      outputSelection: { "*": { "*": ["abi", "evm.bytecode.object"] } },
    },
  };
  const out = JSON.parse(solc.compile(JSON.stringify(input)));
  const errors = (out.errors || []).filter((e) => e.severity === "error");
  if (errors.length) {
    errors.forEach((e) => console.error(e.formattedMessage));
    process.exit(1);
  }
  const compiled = out.contracts["MedTrace.sol"]["MedTrace"];

  const rpc = process.env.RPC_URL || "http://127.0.0.1:8545";
  const provider = new ethers.JsonRpcProvider(rpc);
  const signer = process.env.PRIVATE_KEY
    ? new ethers.Wallet(process.env.PRIVATE_KEY, provider)
    : await provider.getSigner(0);

  const factory = new ethers.ContractFactory(compiled.abi, "0x" + compiled.evm.bytecode.object, signer);
  const contract = await factory.deploy();
  await contract.waitForDeployment();
  const address = await contract.getAddress();

  fs.writeFileSync(
    path.join(__dirname, "deployed.json"),
    JSON.stringify({ address, abi: compiled.abi, rpc }, null, 2)
  );
  console.log("MedTrace deployed at", address);
}

main().catch((e) => {
  console.error(e);
  process.exit(1);
});
