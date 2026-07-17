// falsenegatives.ts documents the capability lint's known, accepted limits
// (spec 1.3: lint is heuristic and advisory, not proof of absence). Two
// known false negatives live here: a dynamic import whose specifier is a
// variable is never followed, and a capability hidden behind eval is never
// scanned, because DetectJS matches literal text line by line and never
// evaluates or interprets the source it reads. One known false positive
// lives here too: a commented out call still matches the same line
// anchored pattern a live call would, because DetectJS does not parse
// comments out; that is an accepted, documented limitation, not a defect.

async function loadDynamic(moduleName) {
	return import(moduleName);
}

function loadHidden(hexDecoded) {
	return eval(hexDecoded);
}

// require("http")
