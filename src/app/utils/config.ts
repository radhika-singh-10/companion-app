import fs from "fs";
import path from "path";
import { Config } from "twilio/lib/twiml/VoiceResponse";

class ConfigManager {
  private static instance: ConfigManager;
  private config: any;

  private constructor() {
    const safePath = path.resolve(process.cwd(), "companions", "companions.json");
    const allowedBase = path.resolve(process.cwd(), "companions");
    if (!safePath.startsWith(allowedBase + path.sep) && safePath !== allowedBase) {
      throw new Error("Invalid configuration file path.");
    }
    const data = fs.readFileSync(safePath, "utf8");
    this.config = JSON.parse(data);
  }

  public static getInstance(): ConfigManager {
    if (!ConfigManager.instance) {
      ConfigManager.instance = new ConfigManager();
    }
    return ConfigManager.instance;
  }

  // Only these fields may be returned to callers — add fields here deliberately.
  private static readonly ALLOWED_CONFIG_FIELDS: ReadonlyArray<string> = [
    "name",
    "voice",
    "language",
    "greeting",
    "personality",
    "model",
  ];

  private sanitizeConfig(raw: any): Record<string, unknown> {
    const sanitized: Record<string, unknown> = {};
    for (const field of ConfigManager.ALLOWED_CONFIG_FIELDS) {
      if (Object.prototype.hasOwnProperty.call(raw, field)) {
        sanitized[field] = raw[field];
      }
    }
    return sanitized;
  }

  private static readonly ALLOWED_FIELD_NAMES = new Set(["name", "id", "type", "category"]);

  public getConfig(fieldName: string, configValue: string) {
    //).filter((c: any) => c.name === companionName);
    try {
      const dangerousKeys = new Set(["__proto__", "constructor", "prototype"]);
      if (dangerousKeys.has(fieldName) || !ConfigManager.ALLOWED_FIELD_NAMES.has(fieldName)) {
        throw new Error("Invalid field name.");
      }
      if (!!this.config && this.config.length !== 0) {
        const result = this.config.filter(
          (c: any) => Object.prototype.hasOwnProperty.call(c, fieldName) && c[fieldName] === configValue
        );
        if (result.length !== 0) {
          return this.sanitizeConfig(result[0]);
        }
      }
    } catch (e) {
      console.error("Configuration lookup failed due to an internal error.");
    }
  }
}

export default ConfigManager;
