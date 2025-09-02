use std::fs::File;
use std::io::{self, Read, Write};
use std::time::Duration;
use std::thread;

use opensk::api::connection::{HidConnection, RecvStatus, UsbEndpoint};
use opensk::ctap::status_code::{Ctap2StatusCode, CtapResult};

use uhid_virt::{Bus, CreateParams, OutputEvent, StreamError, UHIDDevice};

// Minimal FIDO (CTAP) HID report descriptor: 64-byte OUT and 64-byte IN, no report IDs.
const FIDO_RDESC: [u8; 34] = [
    0x06, 0xD0, 0xF1, // Usage Page (FIDO Alliance)
    0x09, 0x01,       // Usage (U2F/FIDO Device)
    0xA1, 0x01,       // Collection (Application)

    0x09, 0x20,       // Usage (Data In)   - Host <- Device
    0x15, 0x00,       //   Logical Min 0
    0x26, 0xFF, 0x00, //   Logical Max 255
    0x75, 0x08,       //   Report Size 8
    0x95, 0x40,       //   Report Count 64
    0x81, 0x02,       //   Input (Data,Var,Abs)

    0x09, 0x21,       // Usage (Data Out)  - Host -> Device
    0x15, 0x00,       //   Logical Min 0
    0x26, 0xFF, 0x00, //   Logical Max 255
    0x75, 0x08,       //   Report Size 8
    0x95, 0x40,       //   Report Count 64
    0x91, 0x02,       //   Output (Data,Var,Abs)

    0xC0,             // End Collection
];

pub struct FidoHid<T: Read + Write>(UHIDDevice<T>);

impl<T: Read + Write> FidoHid<T> {
    pub fn new() -> io::Result<FidoHid<File>> {
        let create_params = CreateParams {
            name: "virt-fido2-demo".to_string(),
            phys: "uhid-virt".to_string(),
            uniq: "virt-fido2-0001".to_string(),
            bus: Bus::USB,
            vendor: 0x1209,
            product: 0x0001,
            version: 0x0001,
            country: 0,
            rd_data: FIDO_RDESC.to_vec(),
        };

        let dev = UHIDDevice::create(create_params)?;
        Ok(FidoHid(dev))
    }
}

/// Implements the `HidConnection` trait for a `FidoHid` device, which is a wrapper
/// around a Linux `uhid` (user-space HID) stream.
///
/// This implementation translates between the generic `HidConnection` interface used by the
/// CTAP2 authenticator logic and the specific event-driven model of the `uhid` kernel API.
impl<T: Read + Write> HidConnection for FidoHid<T> {
    fn send(&mut self, buf: &[u8; 64], _endpoint: UsbEndpoint) -> CtapResult<()> {
        self.0.write(buf).map_err(|_| Ctap2StatusCode::CTAP2_ERR_ACTION_TIMEOUT)?;
        Ok(())
    }

    fn recv(&mut self, buf: &mut [u8; 64], timeout_ms: usize) -> CtapResult<RecvStatus> {
        match self.0.read() {
            Ok(OutputEvent::Start { .. }) => println!("UHID: start"),
            Ok(OutputEvent::Open) => println!("UHID: open"),
            Ok(OutputEvent::Close) => println!("UHID: close"),
            Ok(OutputEvent::Stop) => panic!("UHID: device stopped"),
            Ok(OutputEvent::Output { data }) => {
                // The first byte in UHID is always the report ID, even if not included in the descriptor
                buf.copy_from_slice(&data[1..65]);
                return Ok(RecvStatus::Received(UsbEndpoint::MainHid));
            }
            Ok(OutputEvent::GetReport { id, .. }) => {
                self.0.write_get_report_reply(id, 0, vec![0u8; 64])
                    .map_err(|_| Ctap2StatusCode::CTAP2_ERR_ACTION_TIMEOUT)?;
            }
            Ok(OutputEvent::SetReport { id, .. }) => {
                self.0.write_set_report_reply(id, 0)
                    .map_err(|_| Ctap2StatusCode::CTAP2_ERR_ACTION_TIMEOUT)?;
            }
            Err(StreamError::Io(e)) if e.kind() == std::io::ErrorKind::WouldBlock => {
                thread::sleep(Duration::from_millis(timeout_ms as u64));
            }
            Err(StreamError::Io(e)) => {
                eprintln!("UHID read error: {}", e);
                thread::sleep(Duration::from_millis(timeout_ms as u64));
            }
            Err(StreamError::UnknownEventType(e)) => {
                eprintln!("UHID unknown event: {}", e);
                return Err(Ctap2StatusCode::CTAP2_ERR_INVALID_OPTION);
            }
        }

        Ok(RecvStatus::Timeout)
    }
}
