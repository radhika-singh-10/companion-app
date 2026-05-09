"use server";

// server action to allow configuration of LLM from .env.local

import dotenv from "dotenv";
import * as fs from "fs";
import * as path from "path";


export async function getCompanions() {
  // Anchor the path to this file's directory to avoid working-directory manipulation
  const COMPFILE = path.resolve(__dirname, "companions", "companions.json");
  // run a parse here to force a server side error if the JSON is improperly formatted
  // It's much more difficult to debug client side
  const data = fs.readFileSync(COMPFILE);
  const js = JSON.parse(String(data));
  return String(data);
};
    for (const field of ALLOWED_FIELDS) {
      if (Object.prototype.hasOwnProperty.call(companion, field)) {
        safe[field] = companion[field];
      }
    }
    return safe;
  });

  console.log(`Loaded ${filtered.length} companion(s) from configuration.`);
  return JSON.stringify(filtered);
}