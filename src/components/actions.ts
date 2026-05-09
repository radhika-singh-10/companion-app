"use server";

// server action to allow configuration of LLM from .env.local

import dotenv from "dotenv";
import { parse } from "path";


export async function getCompanions() {
  const COMPFILE = "./companions/companions.json";
  var companions = [];
  // console.log("Loading companion descriptions from "+COMPFILE);
  var fs = require('fs');
  const data = fs.readFileSync(COMPFILE);
  // run a parse here to force a server side error if the JSON is improperly formatted
  // It's much more difficult to debug client side
  var js = JSON.parse(String(data));

  // Apply field allowlist — return only the minimal required fields per companion
  const ALLOWED_FIELDS: (keyof typeof js[0])[] = ["id", "name", "description", "avatar"];
  const filtered = (Array.isArray(js) ? js : []).map((companion: Record<string, unknown>) => {
    const safe: Record<string, unknown> = {};
    for (const field of ALLOWED_FIELDS) {
      if (Object.prototype.hasOwnProperty.call(companion, field)) {
        safe[field] = companion[field];
      }
    }
    return safe;
  });

  return JSON.stringify(filtered);
}