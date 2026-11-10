//! Coverage YAML block mappings, as emitted by libyaml (including quoted
//! binary bin names, document markers, comments and variable indentation).
//! Collections other than mappings and unsigned count scalars are rejected.

pub enum Val {
    Count(u64),
    Map(Vec<(String, Val)>),
}

impl Val {
    pub fn as_count(&self) -> Option<u64> {
        match self { Self::Count(n) => Some(*n), _ => None }
    }
}

struct Line {
    indent: usize,
    key: String,
    value: Option<u64>,
    blank_map: bool,
}

fn unquote(s: &str) -> Result<String, String> {
    if s.starts_with('\'') {
        if !s.ends_with('\'') || s.len() < 2 { return Err("unterminated quoted scalar".into()); }
        return Ok(s[1..s.len()-1].replace("''", "'"));
    }
    if !s.starts_with('"') { return Ok(s.to_string()); }
    if !s.ends_with('"') || s.len() < 2 { return Err("unterminated quoted scalar".into()); }
    let mut out = String::new();
    let mut chars = s[1..s.len()-1].chars();
    while let Some(c) = chars.next() {
        if c != '\\' { out.push(c); continue; }
        let c = chars.next().ok_or("incomplete YAML escape")?;
        match c {
            '0' => out.push('\0'), 'a' => out.push('\x07'), 'b' => out.push('\x08'),
            't' | '\t' => out.push('\t'), 'n' => out.push('\n'), 'v' => out.push('\x0b'),
            'f' => out.push('\x0c'), 'r' => out.push('\r'), 'e' => out.push('\x1b'),
            ' ' | '"' | '/' | '\\' => out.push(c),
            'N' => out.push('\u{85}'), '_' => out.push('\u{a0}'),
            'L' => out.push('\u{2028}'), 'P' => out.push('\u{2029}'),
            'x' | 'u' | 'U' => {
                let width = match c { 'x' => 2, 'u' => 4, _ => 8 };
                let mut code = 0u32;
                for _ in 0..width {
                    code = code.checked_mul(16).and_then(|n| chars.next().and_then(|c| c.to_digit(16)).and_then(|d| n.checked_add(d))).ok_or("invalid Unicode escape")?;
                }
                out.push(char::from_u32(code).ok_or("invalid Unicode scalar")?);
            }
            _ => return Err(format!("unsupported YAML escape \\{c}")),
        }
    }
    Ok(out)
}

/// Locate delimiters outside single/double quoted scalars.
fn delimiters(s: &str) -> Result<(Option<usize>, Option<usize>), String> {
    let mut quote = None;
    let mut escape = false;
    let mut colon = None;
    for (i,c) in s.char_indices() {
        if escape { escape = false; continue; }
        if quote == Some('"') && c == '\\' { escape = true; continue; }
        if let Some(q) = quote {
            if c == q { quote = None; }
        } else {
            match c {
                '\'' | '"' => quote = Some(c),
                ':' if colon.is_none() && s[i+1..].chars().next().map_or(true, char::is_whitespace) => colon = Some(i),
                '#' if i == 0 || s[..i].chars().last().is_some_and(char::is_whitespace) => return Ok((colon, Some(i))),
                _ => (),
            }
        }
    }
    if quote.is_some() { return Err("unterminated quoted scalar".into()); }
    Ok((colon,None))
}

fn lines(text: &str) -> Result<Vec<Line>, String> {
    let mut out = Vec::new();
    let mut started = false;
    let mut ended = false;
    for (n,raw) in text.trim_start_matches('\u{feff}').lines().enumerate() {
        let body = raw.trim_start_matches(' ');
        let indent = raw.len() - body.len();
        if body.starts_with('\t') { return Err(format!("line {}: tab indentation", n+1)); }
        let (colon,comment) = delimiters(body).map_err(|e| format!("line {}: {e}", n+1))?;
        let content = body[..comment.unwrap_or(body.len())].trim_end();
        if content.is_empty() || content.starts_with("%YAML ") { continue; }
        if content == "---" {
            if started || ended { return Err("multiple YAML documents are not coverage mappings".into()); }
            started = true; continue;
        }
        if content == "..." { ended = true; continue; }
        if ended { return Err("content after YAML document end".into()); }
        started = true;
        if content == "{}" && out.is_empty() { ended = true; continue; }
        let colon = colon.ok_or_else(|| format!("line {}: expected 'key:'",n+1))?;
        let key = unquote(content[..colon].trim())?;
        if key.is_empty() { return Err("empty coverage mapping key".into()); }
        let rest = content[colon+1..].trim();
        let (value,blank_map) = if rest.is_empty() { (None,false) }
            else if rest == "{}" { (None,true) }
            else {
                let scalar = unquote(rest)?.replace('_', "");
                let scalar = scalar.strip_prefix('+').unwrap_or(&scalar);
                let count = if let Some(hex) = scalar.strip_prefix("0x") { u64::from_str_radix(hex,16) }
                    else if let Some(octal) = scalar.strip_prefix("0o") { u64::from_str_radix(octal,8) }
                    else { scalar.parse::<u64>() };
                (Some(count.map_err(|_| format!("line {}: '{rest}' is not a coverage count", n+1))?),false)
            };
        out.push(Line { indent,key,value,blank_map });
    }
    Ok(out)
}

fn block(lines: &[Line], i: &mut usize, indent: usize) -> Result<Val, String> {
    let mut map = Vec::new();
    while *i < lines.len() {
        let l = &lines[*i];
        if l.indent < indent { break; }
        if l.indent > indent { return Err(format!("unexpected indentation before '{}'", l.key)); }
        let key = l.key.clone();
        let value = l.value;
        let blank = l.blank_map;
        *i += 1;
        let value = if let Some(v) = value { Val::Count(v) }
            else if blank { Val::Map(Vec::new()) }
            else if lines.get(*i).is_some_and(|next| next.indent > indent) {
                let child_indent = lines[*i].indent;
                block(lines,i,child_indent)?
            } else { Val::Map(Vec::new()) };
        map.push((key,value));
    }
    Ok(Val::Map(map))
}

pub fn parse(text: &str) -> Result<Val, String> {
    let ls = lines(text)?;
    if ls.is_empty() { return Ok(Val::Map(Vec::new())); }
    if ls[0].indent != 0 { return Err("root mapping is indented".into()); }
    let mut i = 0;
    let root = block(&ls,&mut i,0)?;
    if i != ls.len() { return Err("trailing content after root mapping".into()); }
    Ok(root)
}
