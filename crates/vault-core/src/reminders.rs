#![forbid(unsafe_code)]

use uuid::Uuid;
use vault_models::{ItemKind, VaultItem};

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Deadline {
    pub item_id: Uuid,
    pub kind: ItemKind,
    pub title: String,
    pub label: &'static str,
    pub date: String,
    pub days_until: i64,
}

/// Strictly parse `YYYY-MM-DD` (exactly 10 ASCII chars, `-` at index 4 and 7).
/// Returns `None` for anything else, including empty strings, free text,
/// out-of-range months/days, and non-leap-year Feb 29.
pub fn parse_ymd(s: &str) -> Option<(i32, u32, u32)> {
    let bytes = s.as_bytes();
    if bytes.len() != 10 {
        return None;
    }
    if bytes[4] != b'-' || bytes[7] != b'-' {
        return None;
    }
    for (index, byte) in bytes.iter().enumerate() {
        if index == 4 || index == 7 {
            continue;
        }
        if !byte.is_ascii_digit() {
            return None;
        }
    }
    let digit = |i: usize| -> i32 { i32::from(bytes[i] - b'0') };
    let year = digit(0) * 1000 + digit(1) * 100 + digit(2) * 10 + digit(3);
    let month = (digit(5) * 10 + digit(6)) as u32;
    let day = (digit(8) * 10 + digit(9)) as u32;
    if !(1..=12).contains(&month) {
        return None;
    }
    if day == 0 || day > days_in_month(year, month) {
        return None;
    }
    Some((year, month, day))
}

fn is_leap_year(year: i32) -> bool {
    year % 4 == 0 && (year % 100 != 0 || year % 400 == 0)
}

fn days_in_month(year: i32, month: u32) -> u32 {
    match month {
        1 | 3 | 5 | 7 | 8 | 10 | 12 => 31,
        4 | 6 | 9 | 11 => 30,
        2 => {
            if is_leap_year(year) {
                29
            } else {
                28
            }
        }
        _ => 0,
    }
}

/// Days since the Unix epoch (1970-01-01) using Howard Hinnant's
/// days-from-civil algorithm. Pure integer math, no time zones or DST.
pub fn days_since_civil(y: i32, m: u32, d: u32) -> i64 {
    let y = i64::from(y);
    let m = i64::from(m);
    let d = i64::from(d);
    let y_adj = if m <= 2 { y - 1 } else { y };
    let era = if y_adj >= 0 {
        y_adj / 400
    } else {
        (y_adj - 399) / 400
    };
    let yoe = y_adj - era * 400;
    let mp = if m > 2 { m - 3 } else { m + 9 };
    let doy = (153 * mp + 2) / 5 + d - 1;
    let doe = yoe * 365 + yoe / 4 - yoe / 100 + doy;
    era * 146_097 + doe - 719_468
}

pub fn civil_from_days(z: i64) -> (i32, u32, u32) {
    let z = z + 719_468;
    let era = if z >= 0 { z } else { z - 146_096 } / 146_097;
    let doe = (z - era * 146_097) as u64;
    let yoe = (doe - doe / 1460 + doe / 36_524 - doe / 146_096) / 365;
    let y = yoe as i64 + era * 400;
    let doy = doe - (365 * yoe + yoe / 4 - yoe / 100);
    let mp = (5 * doy + 2) / 153;
    let d = doy - (153 * mp + 2) / 5 + 1;
    let m = if mp < 10 { mp + 3 } else { mp - 9 };
    let y = y + i64::from(m <= 2);
    (y as i32, m as u32, d as u32)
}

/// Derive deadlines from vault items using only local date math.
///
/// Sources:
/// - `Document` → `expiry` ("Document expiry")
/// - `Insurance` → `renewal` ("Insurance renewal")
/// - `Receipt` → `return_by` ("Return deadline") or `refund_due` ("Refund due")
/// - `Vehicle` → `renewal` ("Vehicle renewal")
/// - `Possession` → `warranty_expiry` ("Warranty expiry")
/// - `Subscription` → `next_renewal` ("Subscription renewal")
///
/// Items with missing, empty, or unparseable dates are skipped.
/// Results are sorted ascending by `(days_until, title, item_id)` with no
/// truncation; the caller applies any display limits.
pub fn collect_deadlines(items: &[VaultItem], today: (i32, u32, u32)) -> Vec<Deadline> {
    let today_days = days_since_civil(today.0, today.1, today.2);
    let mut deadlines = Vec::new();
    for item in items {
        let (field, label): (&str, &'static str) = match item.kind {
            ItemKind::Document => ("expiry", "Document expiry"),
            ItemKind::Insurance => ("renewal", "Insurance renewal"),
            ItemKind::Receipt => {
                let status = item
                    .fields
                    .get("tracking_status")
                    .map_or("", String::as_str);
                match status {
                    "" => continue,
                    "refund_pending" => ("refund_due", "Refund due"),
                    "refunded" | "kept" | "returned" => continue,
                    _ => ("return_by", "Return deadline"),
                }
            }
            ItemKind::Vehicle => ("renewal", "Vehicle renewal"),
            ItemKind::Possession => ("warranty_expiry", "Warranty expiry"),
            ItemKind::Subscription => ("next_renewal", "Subscription renewal"),
            _ => continue,
        };
        let raw = item.fields.get(field).map_or("", String::as_str);
        let date_str = raw.trim();
        if date_str.is_empty() {
            continue;
        }
        let Some((y, m, d)) = parse_ymd(date_str) else {
            continue;
        };
        deadlines.push(Deadline {
            item_id: item.id,
            kind: item.kind,
            title: item.title.clone(),
            label,
            date: date_str.to_owned(),
            days_until: days_since_civil(y, m, d) - today_days,
        });
    }
    deadlines.sort_by(|a, b| {
        a.days_until
            .cmp(&b.days_until)
            .then_with(|| a.title.cmp(&b.title))
            .then_with(|| a.item_id.cmp(&b.item_id))
    });
    deadlines
}

#[cfg(test)]
mod tests {
    use super::*;

    fn today() -> (i32, u32, u32) {
        (2024, 5, 10)
    }

    #[test]
    fn overdue_deadline_has_negative_days_until() {
        let item = VaultItem::document("Passport", "P123", "Gov", "2024-05-01", "");
        let deadlines = collect_deadlines(&[item], today());
        assert_eq!(deadlines.len(), 1);
        assert_eq!(deadlines[0].label, "Document expiry");
        assert_eq!(deadlines[0].date, "2024-05-01");
        assert_eq!(
            deadlines[0].days_until,
            days_since_civil(2024, 5, 1) - days_since_civil(2024, 5, 10)
        );
        assert!(deadlines[0].days_until < 0);
    }

    #[test]
    fn deadlines_sort_by_days_then_title_then_id() {
        let soon_b = VaultItem::insurance("B policy", "P", "T", "N", "2024-05-12", "");
        let soon_a = VaultItem::insurance("A policy", "P", "T", "N", "2024-05-12", "");
        let later = VaultItem::vehicle(
            "Car",
            "Make",
            "Model",
            "2021",
            "REG",
            "VIN",
            "2024-06-01",
            "",
        );
        let overdue = VaultItem::document("Passport", "P123", "Gov", "2024-05-01", "");
        let deadlines = collect_deadlines(&[later, soon_b, soon_a, overdue], today());
        assert_eq!(deadlines.len(), 4);
        assert_eq!(deadlines[0].title, "Passport");
        assert_eq!(deadlines[1].title, "A policy");
        assert_eq!(deadlines[2].title, "B policy");
        assert_eq!(deadlines[3].title, "Car");
        assert!(
            deadlines
                .windows(2)
                .all(|w| w[0].days_until <= w[1].days_until)
        );

        // Same date and title falls back to item_id ordering.
        let mut first = VaultItem::document("Same", "N", "I", "2024-05-15", "");
        let mut second = VaultItem::document("Same", "N", "I", "2024-05-15", "");
        if first.id < second.id {
            std::mem::swap(&mut first, &mut second);
        }
        assert!(first.id > second.id);
        let tied = collect_deadlines(&[first.clone(), second.clone()], today());
        assert_eq!(tied.len(), 2);
        assert_eq!(tied[0].item_id, second.id);
        assert_eq!(tied[1].item_id, first.id);
    }

    #[test]
    fn empty_and_unparseable_dates_are_skipped() {
        let empty = VaultItem::document("Empty", "N", "I", "", "");
        let blank = VaultItem::document("Blank", "N", "I", "   ", "");
        let free_text = VaultItem::insurance("Free", "P", "T", "N", "next spring", "");
        let bad_month = VaultItem::vehicle(
            "BadMonth",
            "Make",
            "Model",
            "2021",
            "REG",
            "VIN",
            "2024-13-01",
            "",
        );
        let bad_day = VaultItem::possession(
            "BadDay",
            "",
            "",
            "Brand",
            "Model",
            "SN",
            "2024-01-01",
            "100",
            "Store",
            "2024-02-30",
            "",
        );
        let bad_sep = VaultItem::document("BadSep", "N", "I", "2024/05/01", "");
        let valid = VaultItem::document("Valid", "N", "I", "2024-05-20", "");
        let items = vec![empty, blank, free_text, bad_month, bad_day, bad_sep, valid];
        let deadlines = collect_deadlines(&items, today());
        assert_eq!(deadlines.len(), 1);
        assert_eq!(deadlines[0].title, "Valid");
    }

    #[test]
    fn leap_year_feb_29_rules() {
        assert_eq!(parse_ymd("2024-02-29"), Some((2024, 2, 29)));
        assert_eq!(parse_ymd("2023-02-29"), None);
        assert_eq!(parse_ymd("2000-02-29"), Some((2000, 2, 29)));
        assert_eq!(parse_ymd("1900-02-29"), None);

        let item = VaultItem::possession(
            "Laptop",
            "",
            "",
            "Brand",
            "Model",
            "SN",
            "2024-01-01",
            "100",
            "Store",
            "2024-02-29",
            "",
        );
        let deadlines = collect_deadlines(&[item], (2024, 2, 28));
        assert_eq!(deadlines.len(), 1);
        assert_eq!(deadlines[0].days_until, 1);
    }

    #[test]
    fn non_deadline_kinds_are_ignored() {
        let mut note = VaultItem::secure_note("Note", "body");
        note.fields
            .insert("expiry".to_owned(), "2024-05-11".to_owned());
        let mut password =
            VaultItem::password("Login", "user", "secret", "https://example.com", "");
        password
            .fields
            .insert("renewal".to_owned(), "2024-05-11".to_owned());
        let mut financial = VaultItem::financial("Bank", "Bank", "Savings", "USD", "123", "");
        financial
            .fields
            .insert("renewal".to_owned(), "2024-05-11".to_owned());
        let mut property = VaultItem::property("House", "Flat", "Addr", "Own", "Ref", "");
        property
            .fields
            .insert("warranty_expiry".to_owned(), "2024-05-11".to_owned());
        let deadlines = collect_deadlines(&[note, password, financial, property], today());
        assert!(deadlines.is_empty());
    }

    #[test]
    fn labels_and_date_math_match_sources() {
        let doc = VaultItem::document("Doc", "N", "I", "2024-05-10", "");
        let ins = VaultItem::insurance("Ins", "P", "T", "N", "2024-05-10", "");
        let receipt = VaultItem::receipt(
            "Receipt",
            "Store",
            "2024-05-01",
            "100",
            "USD",
            "R-1",
            "return_planned",
            "2024-05-10",
            "",
            "",
        );
        let veh = VaultItem::vehicle(
            "Veh",
            "Make",
            "Model",
            "2021",
            "REG",
            "VIN",
            "2024-05-10",
            "",
        );
        let pos = VaultItem::possession(
            "Pos",
            "",
            "",
            "Brand",
            "Model",
            "SN",
            "2024-01-01",
            "100",
            "Store",
            "2024-05-10",
            "",
        );
        let deadlines = collect_deadlines(&[doc, ins, receipt, veh, pos], today());
        assert_eq!(deadlines.len(), 5);
        for deadline in &deadlines {
            assert_eq!(deadline.days_until, 0);
        }
        let label_for = |title: &str| {
            deadlines
                .iter()
                .find(|d| d.title == title)
                .map(|d| d.label)
                .expect("deadline present")
        };
        assert_eq!(label_for("Doc"), "Document expiry");
        assert_eq!(label_for("Ins"), "Insurance renewal");
        assert_eq!(label_for("Receipt"), "Return deadline");
        assert_eq!(label_for("Veh"), "Vehicle renewal");
        assert_eq!(label_for("Pos"), "Warranty expiry");

        // Unix epoch sanity check for the civil-date conversion.
        assert_eq!(days_since_civil(1970, 1, 1), 0);
        assert_eq!(days_since_civil(1970, 1, 2), 1);
        assert_eq!(days_since_civil(1969, 12, 31), -1);
    }

    #[test]
    fn subscription_renewal_is_a_deadline() {
        let subscription = VaultItem::subscription(
            "Streaming",
            "Provider",
            "Standard",
            "9.99",
            "USD",
            "monthly",
            "2024-05-12",
            "",
        );
        let deadlines = collect_deadlines(&[subscription], today());
        assert_eq!(deadlines.len(), 1);
        assert_eq!(deadlines[0].label, "Subscription renewal");
        assert_eq!(deadlines[0].date, "2024-05-12");
        assert_eq!(deadlines[0].days_until, 2);
    }

    #[test]
    fn strict_format_rejects_non_canonical_inputs() {
        assert_eq!(parse_ymd(""), None);
        assert_eq!(parse_ymd("2024-5-1"), None);
        assert_eq!(parse_ymd("2024-05-01 "), None);
        assert_eq!(parse_ymd(" 2024-05-01"), None);
        assert_eq!(parse_ymd("2024-00-10"), None);
        assert_eq!(parse_ymd("2024-01-00"), None);
        assert_eq!(parse_ymd("2024-04-31"), None);
        assert_eq!(parse_ymd("abcd-ef-gh"), None);
    }

    #[test]
    fn completed_receipt_does_not_create_return_deadline() {
        let refunded = VaultItem::receipt(
            "refunded",
            "Store",
            "2024-05-01",
            "100",
            "USD",
            "R-1",
            "refunded",
            "2024-05-12",
            "2024-05-20",
            "",
        );
        let kept = VaultItem::receipt(
            "kept",
            "Store",
            "2024-05-01",
            "100",
            "USD",
            "R-2",
            "kept",
            "2024-05-12",
            "",
            "",
        );
        assert!(collect_deadlines(&[refunded, kept], today()).is_empty());
    }

    #[test]
    fn untracked_receipt_does_not_create_return_deadline() {
        let receipt = VaultItem::receipt(
            "Not tracked",
            "Store",
            "2024-05-01",
            "100",
            "USD",
            "R-4",
            "",
            "2024-05-12",
            "",
            "",
        );
        assert!(collect_deadlines(&[receipt], today()).is_empty());
    }

    #[test]
    fn refund_pending_receipt_uses_refund_due_deadline() {
        let receipt = VaultItem::receipt(
            "Refund",
            "Store",
            "2024-05-01",
            "100",
            "USD",
            "R-3",
            "refund_pending",
            "2024-05-12",
            "2024-05-15",
            "",
        );
        let deadlines = collect_deadlines(&[receipt], today());
        assert_eq!(deadlines.len(), 1);
        assert_eq!(deadlines[0].label, "Refund due");
        assert_eq!(deadlines[0].date, "2024-05-15");
    }

    #[test]
    fn civil_from_days_round_trips_known_dates() {
        for date in [(1970, 1, 1), (2024, 2, 29), (1900, 1, 1), (2037, 12, 31)] {
            let days = days_since_civil(date.0, date.1, date.2);
            assert_eq!(civil_from_days(days), date);
        }
    }

    #[test]
    fn civil_from_days_round_trips_every_97_days_over_400_years() {
        let start = days_since_civil(1970, 1, 1);
        let end = days_since_civil(2370, 1, 1);
        let mut days = start;
        while days <= end {
            let (y, m, d) = civil_from_days(days);
            assert_eq!(days_since_civil(y, m, d), days);
            days += 97;
        }
    }
}
