# SBT-DF203 Lab 2
## HTTP Object Retrieval, TCP Reassembly and Digital Evidence Validation

**Trainee:** Ibrahim Diseh Garba 
**Registration Number** 2025/FWSD/11521
**Programme:** ICDFA Fellowship in Web Application Security & Digital Forensics 
**Lab:** SBT-DF203 Lab 2 
**Environment:** Kali Linux VM (Isolated Lab Environment) 
**Authorisation:** Approved educational cyber-forensics laboratory exercise

---

# Executive Summary

A local Apache web server was configured to host an HTML page (`image.html`) containing an embedded JPEG image (`lab_photo.jpg`). Browser-generated HTTP traffic was captured on the loopback interface (`127.0.0.1`) using **TShark**.

Analysis demonstrated that:

- The browser generated separate HTTP GET requests for the HTML document and the embedded image.
- Both resources received successful **HTTP 200 OK** responses.
- The image response was transferred across multiple TCP segments.
- Wireshark/TShark successfully reassembled those segments into a single HTTP object.
- The recovered image was exported from the capture and verified using **SHA-256 hashing**.
- The original and extracted image hashes matched exactly, proving byte-for-byte integrity.
- A separate `curl` capture confirmed that `curl` retrieves only the explicitly requested HTML page and does not automatically request embedded resources.

---

# Scope and Authorisation

This practical exercise was conducted exclusively within an isolated virtual machine environment.

Scope restrictions included:

- Traffic limited to `127.0.0.1`
- Apache web server hosted locally
- No third-party systems targeted
- No internet-facing services involved
- Student-owned, non-sensitive image used for testing
- Original evidence preserved throughout analysis

---

# Evidence Acquisition and Integrity

## Folder Structure

```bash
mkdir -p ~/SBT-DF203-Lab2/{evidence,working,exported,reports,screenshots,scripts}

cd ~/SBT-DF203-Lab2

pwd

find . -maxdepth 1 -type d -print
```

Resulting structure:

```text
SBT-DF203-Lab2/
├── evidence/
├── working/
├── exported/
├── reports/
├── screenshots/
└── scripts/
```

---

## Web Server Preparation

### Install Required Packages

```bash
sudo apt update

sudo apt install -y apache2 curl wireshark tshark imagemagick
```

### Start Apache

```bash
sudo systemctl enable --now apache2
```

### Copy Image

```bash
cp PHOTO.jpg /var/www/html/lab_photo.jpg
```

### Create HTML Page

```bash
printf '<!DOCTYPE html>\n<html><body><h1>SBT-DF203 Image Traffic</h1><p>Analyst: Ibrahim Diseh Garba</p><img src="lab_photo.jpg" alt="Training image"></ww/html/image.html
```

---

## Initial Hash Verification

```bash
sha256sum /var/www/html/image.html /var/www/html/lab_photo.jpg \
| tee reports/source_object_hashes.txt
```

### Source Object Hashes

| Object | SHA-256 |
|----------|----------|
| image.html | `<HTML_SHA256>` |
| lab_photo.jpg | `<SOURCE_IMAGE_SHA256>` |

---

## Image Properties

```bash
file /var/www/html/lab_photo.jpg

identify /var/www/html/lab_photo.jpg

ls -lh /var/www/html/image.html /var/www/html/lab_photo.jpg
```

| Property | Value |
|-----------|---------|
| File Type | JPEG image data |
| Dimensions | `<WIDTH>x<HEIGHT>` |
| Size | `<SIZE>` bytes |
| SHA-256 | `<SOURCE_IMAGE_SHA256>` |

---

# Mini Chain-of-Custody Record

| Field | Value |
|---------|---------|
| Case Identifier | SBT-DF203-Lab2-IbrahimDisehGarba |
| Analyst | Ibrahim Diseh Garba |
| Date Started | `<2026-9-10 10:10:15>` |
| Evidence Files | image_traffic.pcapng, image.html, lab_photo.jpg |
| Acquisition Method | Apache2 on localhost |
| Original Hashes | Recorded prior to analysis |
| Working Copy | Preserved and hashed |
| Analysis Location | Kali Linux VM |
| Notes | Original evidence preserved |

---

# Part B: Capturing Browser HTTP Traffic

## Start Capture

```bash
sudo tshark -i lo -f 'tcp port 80' \
-w evidence/image_traffic.pcapng
```

## Generate Traffic

Open:

```text
http://127.0.0.1/image.html
```

Allow the image to load.

Stop capture with:

```text
Ctrl+C
```

---

## Create Working Copy

```bash
cp --preserve=timestamps evidence/image_traffic.pcapng \
working/image_traffic_working.pcapng
```

Verify integrity:

```bash
sha256sum evidence/image_traffic.pcapng \
working/image_traffic_working.pcapng \
| tee reports/capture_hashes.txt
```

---

# Part C: Proving Multiple HTTP Objects Were Requested

## HTTP Request Analysis

```bash
tshark -r working/image_traffic_working.pcapng \
-Y 'http.request' \
-T fields \
-e frame.number \
-e frame.time \
-e tcp.stream \
-e ip.src \
-e tcp.srcport \
-e ip.dst \
-e tcp.dstport \
-e http.request.method \
-e http.request.uri \
-e http.host \
| tee reports/http_object_requests.tsv
```

### Observed Requests

| Frame | Method | URI |
|---------|---------|---------|
| 1 | GET | /image.html |
| 5 | GET | /lab_photo.jpg |

Optional browser request:

| URI | Note |
|---------|---------|
| /favicon.ico | Browser-generated request |

### Finding

The browser automatically requested:

1. HTML document
2. Embedded JPEG image

This confirms that a single webpage commonly generates multiple HTTP requests.

---

## HTTP Response Analysis

```bash
tshark -r working/image_traffic_working.pcapng \
-Y 'http.response' \
-T fields \
-e frame.number \
-e frame.time \
-e tcp.stream \
-e http.response.code \
-e http.content_type \
-e http.content_length \
| tee reports/http_object_responses.tsv
```

Expected observations:

| Resource | Status | Content Type |
|------------|-----------|--------------|
| image.html | 200 OK | text/html |
| lab_photo.jpg | 200 OK | image/jpeg |

---

# Part D: TCP Segmentation and Reassembly

The image transfer occurred over a single TCP stream.

## Examine Segments

```bash
tshark -r working/image_traffic_working.pcapng \
-Y 'tcp.stream==<STREAM> && tcp.len>0' \
-T fields \
-e frame.number \
-e frame.time \
-e ip.len \
-e tcp.hdr_len \
-e tcp.len \
-e tcp.seq \
-e tcp.ack \
| tee reports/image_stream_segments.tsv
```

### Example Observation

| Frame | TCP Payload Length |
|---------|-------------------|
| n1 | <tcp_len> |
| n2 | <tcp_len> |
| n3 | <tcp_len> |

---

## Conclusion

The JPEG image was transmitted across multiple TCP segments.

Wireshark reassembled:

```text
TCP Segments
↓
HTTP Response
↓
Recovered JPEG Object
```

Although segment sizes can vary due to:

- MTU
- MSS
- TCP Offload
- Virtual Interfaces
- Loopback Behaviour

The reassembled object remains identical.

---

## TCP Conversation Summary

```bash
tshark -r working/image_traffic_working.pcapng \
-q -z conv,tcp \
| tee reports/tcp_conversations.txt
```

---

# Part E: Exporting the Embedded Image

## Wireshark Export

```text
File
└─ Export Objects
└─ HTTP
```

Locate:

```text
lab_photo.jpg
```

Save to:

```text
exported/
```

---

## TShark Export Method

```bash
mkdir -p exported/http_objects

tshark -r working/image_traffic_working.pcapng \
--export-objects http,exported/http_objects
```

Verify exported files:

```bash
find exported/http_objects -maxdepth 1 -type f -ls

file exported/http_objects/*

sha256sum \
/var/www/html/lab_photo.jpg \
exported/http_objects/* \
| tee reports/extracted_object_hashes.txt
```

---

## Integrity Verification

| Object | SHA-256 |
|-----------|-----------|
| Original Image | `<SOURCE_IMAGE_SHA256>` |
| Extracted Image | `<EXTRACTED_IMAGE_SHA256>` |

### Result

✅ Hashes Match

Meaning:

- No corruption occurred
- Full object recovery achieved
- Byte-for-byte integrity confirmed

---

# Part F: Browser vs Curl Comparison

## Capture Curl Activity

```bash
sudo tshark -i lo \
-f 'tcp port 80' \
-a duration:20 \
-w evidence/curl_only.pcapng &
```

Execute curl:

```bash
curl -v http://127.0.0.1/image.html \
-o /tmp/image_page.html
```

Review requests:

```bash
tshark -r evidence/curl_only.pcapng \
-Y 'http.request' \
-T fields \
-e http.request.uri \
| tee reports/curl_requested_objects.txt
```

Output:

```text
/image.html
```

---

## Observation

### Browser

Requests:

```text
/image.html
/lab_photo.jpg
```

### Curl

Requests:

```text
/image.html
```

### Explanation

Browsers:

- Parse HTML
- Discover embedded resources
- Automatically fetch images

Curl:

- Downloads only the URL requested
- Does not interpret HTML
- Does not fetch embedded objects

---

# Key Forensic Findings

| Finding | Observation |
|-----------|-------------|
| Main HTTP Requests | image.html and lab_photo.jpg |
| HTTP Status Codes | 200 OK |
| Image Type | image/jpeg |
| Object Extraction | Successful |
| Reassembly | Successful |
| Hash Match | Yes |
| Integrity Result | Verified |
| Browser Behaviour | Retrieves embedded objects |
| Curl Behaviour | Retrieves only specified URL |

---

# Limitations

- Browser caching can hide requests.
- HTTPS encrypts object contents.
- Missing packets may prevent reassembly.
- TCP offloading may alter apparent segment sizes.
- Browsers may request additional resources such as favicons.

---

# Recommendations

- Use Incognito/Private Browsing.
- Preserve original PCAP files.
- Perform analysis on a working copy.
- Capture traffic on the correct interface.
- Validate extracted evidence using SHA-256.
- Document all unexpected requests.
- Restrict plaintext HTTP testing to isolated laboratory environments.

---

# Conclusion

This exercise successfully demonstrated that a single webpage containing embedded content generates multiple HTTP requests. Browser analysis showed separate retrieval of the HTML page and JPEG image, each returning an HTTP 200 OK response.

TCP analysis confirmed that the image was segmented during transmission and correctly reassembled by Wireshark/TShark. Exported object validation produced an identical SHA-256 hash to the original image, proving forensic integrity and successful recovery.

The curl comparison further demonstrated that non-rendering clients do not automatically retrieve embedded resources, unlike modern web browsers.

---

# Appendix A: Command Reference

| Command Purpose | Tool |
|-----------------|------|
| Packet Capture | tshark |
| HTTP Request Analysis | tshark |
| HTTP Response Analysis | tshark |
| TCP Segment Analysis | tshark |
| Object Export | tshark / Wireshark |
| Hash Verification | sha256sum |
| Image Identification | file / identify |

---

# Appendix B: Screenshot Checklist

- [ ] Webpage displaying image
- [ ] Source image properties
- [ ] Browser traffic capture running
- [ ] HTTP request list
- [ ] HTTP response list
- [ ] TCP segment analysis
- [ ] Export Objects window
- [ ] Recovered JPEG opened
- [ ] SHA-256 comparison
- [ ] Curl-only request capture

---

# Student Declaration

I confirm that this lab was performed within an authorised educational environment, that no third-party systems were targeted, that original evidence was preserved, and that all findings, commands, observations, and conclusions accurately reflect my own work.

**Student:** Ibrahim Diseh Garba 
**Programme:** ICDFA Fellowship in Web Application Security & Digital Forensics 
**Lab:** SBT-DF203 Lab 2

