//! A set of rules.

use regex::Regex;

/// A set of rules.
pub struct RuleSet {
    rules: Vec<Regex>,
}

impl RuleSet {
    /// Creates a empty rule set.
    pub fn new() -> RuleSet {
        RuleSet { rules: Vec::new() }
    }

    /// Inserts a rule into the set.
    pub fn insert(&mut self, rule: Regex) {
        self.rules.push(rule);
    }

    /// Checks the given rule against all rules in the set.
    pub fn contains(&self, data: &str) -> bool {
        self.rules.iter().any(|r| r.is_match(data))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_rule_set() {
        let rules = [r"(^|\.)030buy\.com$", r"(^|\.)12vpn\.com$", "127.0.0.1"];

        let mut rule_set = RuleSet::new();

        for rule in rules {
            rule_set.insert(Regex::new(rule).unwrap());
        }

        assert_eq!(rule_set.contains("030buy.com"), true);
        assert_eq!(rule_set.contains("12vpn.com"), true);
        assert_eq!(rule_set.contains(".12vpn.com"), true);
        assert_eq!(rule_set.contains("34.12vpn.com"), true);
        assert_eq!(rule_set.contains("127.0.0.1"), true);

        assert_eq!(rule_set.contains("1112vpn.com"), false);
        assert_eq!(rule_set.contains("12vpn.com "), false);
        assert_eq!(rule_set.contains("12vpn.comm"), false);
        assert_eq!(rule_set.contains("2vpn.net.com"), false);
        assert_eq!(rule_set.contains("2vpn.netccom"), false);
        assert_eq!(rule_set.contains("127.0.0.0"), false);
    }
}
