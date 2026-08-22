/// Advances one encrypted output record and returns newly deliverable
/// plaintext bytes. A partial authenticated record is unusable by the peer,
/// so it is credited exactly once, only when the complete record is written.
#[inline]
pub fn complete_record_write(
    offset: &mut usize,
    record_length: usize,
    plaintext_length: &mut usize,
    written: usize,
) -> u64 {
    *offset = offset.saturating_add(written).min(record_length);
    if *offset == record_length {
        std::mem::take(plaintext_length) as u64
    } else {
        0
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn partial_record_is_not_credited_before_authentication_boundary() {
        let mut offset = 0;
        let mut plaintext = 4096;
        assert_eq!(
            complete_record_write(&mut offset, 4200, &mut plaintext, 2100),
            0
        );
        assert_eq!(offset, 2100);
        assert_eq!(plaintext, 4096);

        // If the next completion is an error, no further call occurs and the
        // connection retires with zero credited bytes for this record.
        assert_eq!(plaintext, 4096);
    }

    #[test]
    fn completed_record_is_credited_exactly_once_across_partial_writes() {
        let mut offset = 0;
        let mut plaintext = 4096;
        assert_eq!(
            complete_record_write(&mut offset, 4200, &mut plaintext, 1000),
            0
        );
        assert_eq!(
            complete_record_write(&mut offset, 4200, &mut plaintext, 3200),
            4096
        );
        assert_eq!(plaintext, 0);
        assert_eq!(
            complete_record_write(&mut offset, 4200, &mut plaintext, 1),
            0
        );
    }
}
