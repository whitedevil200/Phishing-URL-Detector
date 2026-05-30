const { buildLocalIntelligence } = require("../src/main/threat-intelligence-builder");

buildLocalIntelligence({ log: true }).catch((error) => {
  console.error(error);
  process.exit(1);
});
