import type { ArgumentConstraint } from "./types.js";

export interface ConstraintCheckResult {
  passed: boolean;
  reason?: string;
}

/**
 * Evaluates all argument constraints for a single allow rule against call arguments.
 * Fail-closed: if a constrained argument is missing (unless `optional: true`) or has
 * the wrong type, the check fails with a descriptive violation message.
 */
export function evaluateArgumentConstraints(
  constraints: Record<string, ArgumentConstraint> | undefined,
  args: Record<string, unknown> | undefined
): ConstraintCheckResult {
  if (!constraints) {
    return { passed: true };
  }

  const callArgs = args ?? {};

  for (const [argName, rule] of Object.entries(constraints)) {
    const value = callArgs[argName];

    if (value === undefined || value === null) {
      if (rule.optional) {
        continue;
      }
      return {
        passed: false,
        reason: `Argument "${argName}" is required by policy constraints`,
      };
    }

    if (rule.equals !== undefined && value !== rule.equals) {
      return {
        passed: false,
        reason: `Argument "${argName}" must equal ${JSON.stringify(rule.equals)}`,
      };
    }

    if (rule.in !== undefined) {
      const matched = rule.in.some((allowed) => allowed === value);
      if (!matched) {
        return {
          passed: false,
          reason: `Argument "${argName}" must be one of ${JSON.stringify(rule.in)}`,
        };
      }
    }

    if (rule.not_in !== undefined) {
      const blocked = rule.not_in.some((disallowed) => disallowed === value);
      if (blocked) {
        return {
          passed: false,
          reason: `Argument "${argName}" is in disallowed set`,
        };
      }
    }

    if (rule.matches !== undefined) {
      if (typeof value !== "string") {
        return {
          passed: false,
          reason: `Argument "${argName}" must be a string matching /${rule.matches}/`,
        };
      }
      const regex = new RegExp(rule.matches);
      if (!regex.test(value)) {
        return {
          passed: false,
          reason: `Argument "${argName}" failed regex constraint /${rule.matches}/`,
        };
      }
    }

    if (rule.min !== undefined) {
      if (typeof value !== "number" || Number.isNaN(value) || value < rule.min) {
        return {
          passed: false,
          reason: `Argument "${argName}" must be >= ${rule.min}`,
        };
      }
    }

    if (rule.max !== undefined) {
      if (typeof value !== "number" || Number.isNaN(value) || value > rule.max) {
        return {
          passed: false,
          reason: `Argument "${argName}" must be <= ${rule.max}`,
        };
      }
    }

    if (rule.min_length !== undefined) {
      const len = getLength(value);
      if (len === null || len < rule.min_length) {
        return {
          passed: false,
          reason: `Argument "${argName}" length must be >= ${rule.min_length}`,
        };
      }
    }

    if (rule.max_length !== undefined) {
      const len = getLength(value);
      if (len === null || len > rule.max_length) {
        return {
          passed: false,
          reason: `Argument "${argName}" length must be <= ${rule.max_length}`,
        };
      }
    }
  }

  return { passed: true };
}

function getLength(value: unknown): number | null {
  if (typeof value === "string" || Array.isArray(value)) {
    return value.length;
  }
  return null;
}
