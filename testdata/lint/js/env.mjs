// env.mjs is a capability lint fixture (task 4.1, extended in task 4.3 for
// name aware env Symbol capture): every line here is a genuine match for
// the env detection class table (spec 9). The first two lines are dot
// access, the third is bracket access, both name aware; the fourth is a
// bare access the detector cannot resolve to a literal name.

const apiKey = process.env.API_KEY;
console.log(process.env.NODE_ENV);
const bracketKey = process.env["BRACKET_KEY"];
const wholeEnv = process.env;
