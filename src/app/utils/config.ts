import fs from "fs";
import path from "path";
import { Config } from "twilio/lib/twiml/VoiceResponse";

class ConfigManager {
  private static instance: ConfigManager;
  private config: any;

  private constructor() {
    const safePath = path.resolve(__dirname, "../../..", "companions", "companions.json");
    const data = fs.readFileSync(safePath, "utf8");
    const parsed = JSON.parse(data);
    // Guard against prototype pollution: reject objects containing dangerous keys
    const sanitize = (obj: any): any => {
      if (Array.isArray(obj)) {
        return obj.map(sanitize);
      }
      if (obj !== null && typeof obj === "object") {
        const clean: Record<string, any> = {};
        for (const key of Object.keys(obj)) {
          if (key === "__proto__" || key === "constructor" || key === "prototype") {
            continue;
          }
          clean[key] = sanitize(obj[key]);
        }
        return clean;
      }
      return obj;
    };
    this.config = sanitize(parsed);
  }

  public static getInstance(): ConfigManager {
    if (!ConfigManager.instance) {
      ConfigManager.instance = new ConfigManager();
    }
    return ConfigManager.instance;
  }

  // Only these fields may be returned to callers — add fields here deliberately.
  private static readonly ALLOWED_FIELDS: ReadonlyArray<string> = [
    "name",
    "voice",
    "language",
    "greeting",
    "personality",
    "model",
  ];

  private minimise(record: any): Partial<Record<string, unknown>> {
    const safe: Partial<Record<string, unknown>> = {};
    for (const key of ConfigManager.ALLOWED_FIELDS) {
      if (Object.prototype.hasOwnProperty.call(record, key)) {
        safe[key] = record[key];
      }
    }
    return safe;
  }

  public getConfig(fieldName: string, configValue: string) {
    //).filter((c: any) => c.name === companionName);
    try {
      if (!!this.config && this.config.length !== 0) {
        const result = this.config.filter(
          (c: any) => c[fieldName] === configValue
        );
        if (result.length !== 0) {
          return this.minimise(result[0]);
        }
      }
    } catch (e) {
      console.error(e instanceof Error ? e.message : "An unknown error occurred in getConfig");
    }
  }
}

export default ConfigManager;
