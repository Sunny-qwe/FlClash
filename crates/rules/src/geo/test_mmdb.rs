//! A minimal MaxMind DB writer for IPv4 databases, enough to build fixtures.

pub(crate) enum Value {
    Str(String),
    U16(u16),
    U32(u32),
    U64(u64),
    Map(Vec<(String, Value)>),
    Array(Vec<Value>),
}

impl Value {
    pub(crate) fn s(text: &str) -> Value {
        Value::Str(text.to_string())
    }

    pub(crate) fn map(pairs: Vec<(&str, Value)>) -> Value {
        Value::Map(pairs.into_iter().map(|(k, v)| (k.to_string(), v)).collect())
    }
}

fn control(out: &mut Vec<u8>, kind: u8, size: usize) {
    let (ext, kind_bits) = if kind > 7 { (kind - 7, 0) } else { (0, kind) };
    let (size_bits, extra): (u8, Vec<u8>) = if size < 29 {
        (size as u8, vec![])
    } else if size < 285 {
        (29, vec![(size - 29) as u8])
    } else {
        (30, ((size - 285) as u16).to_be_bytes().to_vec())
    };
    out.push((kind_bits << 5) | size_bits);
    if kind > 7 {
        out.push(ext);
    }
    out.extend(extra);
}

fn uint(out: &mut Vec<u8>, kind: u8, value: u64) {
    let bytes: Vec<u8> = value
        .to_be_bytes()
        .into_iter()
        .skip_while(|b| *b == 0)
        .collect();
    control(out, kind, bytes.len());
    out.extend(bytes);
}

fn encode(out: &mut Vec<u8>, value: &Value) {
    match value {
        Value::Str(text) => {
            control(out, 2, text.len());
            out.extend(text.as_bytes());
        }
        Value::U16(n) => uint(out, 5, u64::from(*n)),
        Value::U32(n) => uint(out, 6, u64::from(*n)),
        Value::U64(n) => uint(out, 9, *n),
        Value::Map(pairs) => {
            control(out, 7, pairs.len());
            for (key, value) in pairs {
                encode(out, &Value::Str(key.clone()));
                encode(out, value);
            }
        }
        Value::Array(items) => {
            control(out, 11, items.len());
            for item in items {
                encode(out, item);
            }
        }
    }
}

pub(crate) fn build(database_type: &str, entries: &[(&str, u8, Value)]) -> Vec<u8> {
    let mut data = Vec::new();
    let mut nodes: Vec<[u32; 2]> = vec![[u32::MAX; 2]];
    let mut pointers: Vec<(usize, usize, u32)> = Vec::new();
    for (cidr_ip, len, value) in entries {
        let offset = data.len() as u32;
        encode(&mut data, value);
        let ip: std::net::Ipv4Addr = cidr_ip.parse().unwrap();
        let bits = u32::from(ip);
        let mut node = 0usize;
        for depth in 0..*len {
            let bit = ((bits >> (31 - depth)) & 1) as usize;
            if depth + 1 == *len {
                pointers.push((node, bit, offset));
            } else {
                if nodes[node][bit] == u32::MAX {
                    nodes.push([u32::MAX; 2]);
                    nodes[node][bit] = (nodes.len() - 1) as u32;
                }
                node = nodes[node][bit] as usize;
            }
        }
    }
    let node_count = nodes.len() as u32;
    for (node, bit, offset) in pointers {
        nodes[node][bit] = node_count + 16 + offset;
    }
    let mut out = Vec::new();
    for node in &nodes {
        let [left, right] = node.map(|r| if r == u32::MAX { node_count } else { r });
        out.extend(&left.to_be_bytes()[1..]);
        out.extend(&right.to_be_bytes()[1..]);
    }
    out.extend([0u8; 16]);
    out.extend(data);
    out.extend(b"\xAB\xCD\xEFMaxMind.com");
    let metadata = Value::map(vec![
        ("binary_format_major_version", Value::U16(2)),
        ("binary_format_minor_version", Value::U16(0)),
        ("build_epoch", Value::U64(1)),
        ("database_type", Value::s(database_type)),
        ("description", Value::map(vec![("en", Value::s("test"))])),
        ("ip_version", Value::U16(4)),
        ("languages", Value::Array(vec![Value::s("en")])),
        ("node_count", Value::U32(node_count)),
        ("record_size", Value::U16(24)),
    ]);
    encode(&mut out, &metadata);
    out
}
