use std::fs;

pub fn check(path: Option<&str>, budget: Option<&str>) -> Result<(), String> {
    let (Some(path), Some(budget)) = (path, budget) else {
        return Err("usage: xtask check-size <file> <max-bytes>".to_string());
    };
    let budget: u64 = budget
        .parse()
        .map_err(|_| format!("max-bytes is not a number: {budget}"))?;
    let size = fs::metadata(path)
        .map_err(|err| format!("{path}: {err}"))?
        .len();
    println!("{path}: {size} bytes, budget {budget}");
    if size > budget {
        return Err(format!("{path} is {} bytes over its budget", size - budget));
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    fn file_of(len: usize) -> (tempfile::TempDir, String) {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("core");
        fs::write(&path, vec![0u8; len]).unwrap();
        let path = path.to_string_lossy().into_owned();
        (dir, path)
    }

    #[test]
    fn a_file_at_its_budget_passes() {
        let (_dir, path) = file_of(10);
        assert!(check(Some(&path), Some("10")).is_ok());
    }

    #[test]
    fn a_file_over_its_budget_fails() {
        let (_dir, path) = file_of(11);
        let message = check(Some(&path), Some("10")).unwrap_err();
        assert!(message.contains("1 bytes over"), "{message}");
    }

    #[test]
    fn a_bad_budget_is_reported() {
        let (_dir, path) = file_of(1);
        assert!(check(Some(&path), Some("big")).is_err());
        assert!(check(Some(&path), None).is_err());
    }
}
