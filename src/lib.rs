#![allow(non_camel_case_types)]

mod ngap;

use asn1_codecs::aper::AperCodec;
use std::os::raw::c_char;
use entropic::prelude::*;

// const NGAP_ERR_UNSPECIFIED: isize = -1;
const NGAP_ERR_INVALID_ARG: isize = -2;
const NGAP_ERR_ARBITRARY_FAIL: isize = -3;
const NGAP_ERR_APER_ENCODING: isize = -4;
const NGAP_ERR_OUTPUT_TRUNC: isize = -5;
const NGAP_ERR_EXCLUDED_PDU: isize = -6;

const INITIATING_MESSAGE_EXCL_ID: usize = 1 << 8;
const SUCCESSFUL_OUTCOME_EXCL_ID: usize = 2 << 8;
const UNSUCCESSFUL_OUTCOME_EXCL_ID: usize = 3 << 8;

#[no_mangle]
pub unsafe extern "C" fn ngap_arbitrary_to_structured(buf_in: *mut c_char, in_len: isize, buf_out: *mut c_char, out_max: isize) -> isize {
    let in_len: usize = match in_len.try_into() {
        Ok(l) => l,
        Err(_) => return NGAP_ERR_INVALID_ARG,
    };

    let out_max: usize = match out_max.try_into() {
        Ok(l) => l,
        Err(_) => return NGAP_ERR_INVALID_ARG,
    };

    let in_slice = std::slice::from_raw_parts(buf_in as *const u8, in_len);
    let out_slice = std::slice::from_raw_parts_mut(buf_out as *mut u8, out_max);

    let in_iter = in_slice.iter().chain(std::iter::repeat(&0u8).take(200_000 - in_slice.len())); // Cap total entropy to 200,000 bytes for performance

    let Ok(ngap_message) = ngap::NGAP_PDU::from_finite_entropy(&mut FiniteEntropySource::from_iter(in_iter)) else {
        return NGAP_ERR_ARBITRARY_FAIL
    };

    let mut encoded = asn1_codecs::PerCodecData::new_aper();
    match ngap_message.aper_encode(&mut encoded) {
        Ok(()) => (),
        _ => return NGAP_ERR_APER_ENCODING // If the encoding isn't successful, short-circuit this test
    }

    let aper_message_bytes = encoded.into_bytes();
    let aper_message_slice = aper_message_bytes.as_slice();
    if aper_message_slice.len() > out_max {
        return NGAP_ERR_OUTPUT_TRUNC
    }

    out_slice[..aper_message_slice.len()].copy_from_slice(aper_message_slice);

    match aper_message_slice.len().try_into() {
        Ok(l) => l,
        Err(_) => NGAP_ERR_OUTPUT_TRUNC
    }
}

#[no_mangle]
pub unsafe extern "C" fn ngap_arbitrary_to_structured_exclude(buf_in: *mut c_char, in_len: isize, pdus: *mut isize, pdus_len: isize, buf_out: *mut c_char, out_max: isize) -> isize {
    let pdus_len: usize = match pdus_len.try_into() {
        Ok(l) => l,
        Err(_) => return NGAP_ERR_INVALID_ARG
    };

    let in_len: usize = match in_len.try_into() {
        Ok(l) => l,
        Err(_) => return NGAP_ERR_INVALID_ARG,
    };

    let out_max: usize = match out_max.try_into() {
        Ok(l) => l,
        Err(_) => return NGAP_ERR_INVALID_ARG,
    };

    let in_slice = std::slice::from_raw_parts(buf_in as *const u8, in_len);
    let pdus_slice = std::slice::from_raw_parts(pdus as *const usize, pdus_len);
    let out_slice = std::slice::from_raw_parts_mut(buf_out as *mut u8, out_max);

    let ngap_message = ngap::NGAP_PDU::from_entropy(&mut EntropySource::from_slice(in_slice));

    let pdu_id = match &ngap_message {
        ngap::NGAP_PDU::InitiatingMessage(init_msg) => INITIATING_MESSAGE_EXCL_ID + init_msg.procedure_code.0 as usize,
        ngap::NGAP_PDU::SuccessfulOutcome(success_msg) => SUCCESSFUL_OUTCOME_EXCL_ID + success_msg.procedure_code.0 as usize,
        ngap::NGAP_PDU::UnsuccessfulOutcome(unsuccess_msg) => UNSUCCESSFUL_OUTCOME_EXCL_ID + unsuccess_msg.procedure_code.0 as usize,
    };

    for excluded_pdu in pdus_slice {
        if pdu_id == *excluded_pdu {
            return NGAP_ERR_EXCLUDED_PDU
        }
    }

    let mut encoded = asn1_codecs::PerCodecData::new_aper();
    match ngap_message.aper_encode(&mut encoded) {
        Ok(()) => (),
        _ => return NGAP_ERR_APER_ENCODING // If the encoding isn't successful, short-circuit this test
    }

    let aper_message_bytes = encoded.into_bytes();
    let aper_message_slice = aper_message_bytes.as_slice();
    if aper_message_slice.len() > out_max {
        return NGAP_ERR_OUTPUT_TRUNC
    }

    out_slice[..aper_message_slice.len()].copy_from_slice(aper_message_slice);

    match aper_message_slice.len().try_into() {
        Ok(l) => l,
        Err(_) => NGAP_ERR_OUTPUT_TRUNC
    }
}

#[repr(C)]
pub struct StructuredOutput {
    buf: *mut c_char,
    len: isize,
}

#[no_mangle]
pub unsafe extern "C" fn ngap_msg_len(buf_in: *mut c_char, in_len: isize) -> isize {
    if in_len <= 0 {
        return -1;
    }

    let s = std::slice::from_raw_parts(buf_in as *const u8, in_len as usize);

    // The current implementation just decodes the whole bytes, then encodes it and measures
    // the length in bytes.

    let mut data = asn1_codecs::PerCodecData::from_slice_aper(s);
    let decoded = match ngap::NGAP_PDU::aper_decode(&mut data) {
        Ok(val) => val,
        Err(_) => return -1
    };

    let mut encode_data = asn1_codecs::PerCodecData::new_aper();
    match decoded.aper_encode(&mut encode_data) {
        Ok(_) => (),
        Err(_) => return -1,
    }

    encode_data.length_in_bytes() as isize
}
