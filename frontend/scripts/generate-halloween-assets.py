#!/usr/bin/env python3
"""
Generates the Halloween placeholder assets so the storefront works end to end
before the real photos / sound files arrive.

  * public/halloween/*.svg   stylised placeholder bottles (5 "shots" x 2 products)
  * public/audio/*.mp3       original synthesised ambience, thunder and bell

Everything is created from scratch here (no third-party recordings), so there
is nothing to license. Replace any of it with real photos / recordings later.

Usage (from /frontend):  python3 scripts/generate-halloween-assets.py
Needs: numpy, scipy, ffmpeg (audio only).
"""
import os, subprocess, tempfile, wave
import numpy as np
from scipy import signal

ROOT = os.path.abspath(os.path.join(os.path.dirname(__file__), ".."))
IMG = os.path.join(ROOT, "public", "halloween")
AUD = os.path.join(ROOT, "public", "audio")
os.makedirs(IMG, exist_ok=True); os.makedirs(AUD, exist_ok=True)

# ───────────────────────── SVG PLACEHOLDERS ─────────────────────────
PAL = {
  "nocturne": dict(name="NOCTURNE", liq1="#c8213f", liq2="#4a0614", glass="#2a0a12",
                   glow="#be1230", bg1="#2b0510", bg2="#050204", hi="#ffd9de", cap1="#2a2a2e", cap2="#0c0c0e", ink="#f1e6df"),
  "azur":     dict(name="AZUR", liq1="#8fd0ff", liq2="#1d4f9c", glass="#cfe8ff",
                   glow="#7cc4ff", bg1="#0b1a3a", bg2="#06080f", hi="#ffffff", cap1="#dfe8f2", cap2="#8fa0b5", ink="#e8f1fb"),
}

def defs(p, uid):
    return f'''<defs>
  <linearGradient id="liq{uid}" x1="0" y1="0" x2="0" y2="1"><stop offset="0" stop-color="{p['liq1']}"/><stop offset="1" stop-color="{p['liq2']}"/></linearGradient>
  <linearGradient id="gl{uid}" x1="0" y1="0" x2="1" y2="0"><stop offset="0" stop-color="{p['glass']}" stop-opacity=".30"/><stop offset=".5" stop-color="{p['glass']}" stop-opacity=".08"/><stop offset="1" stop-color="{p['glass']}" stop-opacity=".28"/></linearGradient>
  <linearGradient id="cap{uid}" x1="0" y1="0" x2="1" y2="0"><stop offset="0" stop-color="{p['cap2']}"/><stop offset=".35" stop-color="{p['cap1']}"/><stop offset="1" stop-color="{p['cap2']}"/></linearGradient>
  <filter id="blur{uid}" x="-50%" y="-50%" width="200%" height="200%"><feGaussianBlur stdDeviation="14"/></filter>
  <filter id="soft{uid}" x="-50%" y="-50%" width="200%" height="200%"><feGaussianBlur stdDeviation="5"/></filter>
</defs>'''

def bottle(p, uid, side=False):
    """Bottle drawn in a 400x700 box (origin top-left)."""
    w0, w1 = (90, 310) if not side else (110, 290)
    label_x = 130 if not side else 138
    label_w = 140 if not side else 112
    return f'''<g>
  <ellipse cx="200" cy="668" rx="130" ry="12" fill="#000" opacity=".35" filter="url(#soft{uid})"/>
  <rect x="{w0}" y="250" width="{w1-w0}" height="410" rx="30" fill="url(#gl{uid})" stroke="{p['glass']}" stroke-opacity=".45" stroke-width="2"/>
  <rect x="{w0+12}" y="330" width="{w1-w0-24}" height="318" rx="20" fill="url(#liq{uid})" opacity=".92"/>
  <rect x="170" y="212" width="60" height="42" fill="{p['glass']}" fill-opacity=".25" stroke="{p['glass']}" stroke-opacity=".4"/>
  <rect x="148" y="104" width="104" height="112" rx="8" fill="url(#cap{uid})"/>
  <rect x="148" y="104" width="104" height="8" rx="4" fill="#fff" opacity=".16"/>
  <rect x="{label_x}" y="430" width="{label_w}" height="108" rx="3" fill="#0b0a0c" opacity=".78" stroke="{p['liq1']}" stroke-opacity=".6"/>
  <text x="200" y="492" text-anchor="middle" font-family="Georgia, 'Times New Roman', serif" font-size="{22 if not side else 19}" letter-spacing="5" fill="{p['ink']}">{p['name']}</text>
  <text x="200" y="516" text-anchor="middle" font-family="Georgia, serif" font-size="9" letter-spacing="4" fill="{p['ink']}" opacity=".6">KAEORN</text>
  <rect x="{w0+16}" y="270" width="9" height="360" rx="4" fill="{p['hi']}" opacity=".28"/>
</g>'''

def svg(w, h, body, bg=None):
    r = f'<rect width="{w}" height="{h}" fill="{bg}"/>' if bg else ""
    return f'<svg xmlns="http://www.w3.org/2000/svg" viewBox="0 0 {w} {h}" width="{w}" height="{h}">{body}{r if False else ""}</svg>'

def scene_bg(p, uid, w, h, frost=False):
    return f'''<defs><radialGradient id="bg{uid}" cx=".5" cy=".42" r=".8"><stop offset="0" stop-color="{p['bg1']}"/><stop offset="1" stop-color="{p['bg2']}"/></radialGradient></defs>
<rect width="{w}" height="{h}" fill="url(#bg{uid})"/>
<circle cx="{w/2}" cy="{h*0.45}" r="{w*0.32}" fill="{p['glow']}" opacity=".35" filter="url(#blur{uid})"/>'''

def write(name, content):
    with open(os.path.join(IMG, name), "w", encoding="utf-8") as f: f.write(content)

for key, p in PAL.items():
    u = key[:2]
    # 1. FRONT (transparent, 400x700)
    write(f"{key}-front.svg", f'<svg xmlns="http://www.w3.org/2000/svg" viewBox="0 0 400 700" width="400" height="700" role="img" aria-label="{p["name"]} bottle placeholder">{defs(p,u)}{bottle(p,u)}</svg>')
    # 2. THREE-QUARTER (transparent)
    write(f"{key}-three-quarter.svg", f'<svg xmlns="http://www.w3.org/2000/svg" viewBox="0 0 400 700" width="400" height="700">{defs(p,u)}<g transform="rotate(-6 200 400)">{bottle(p,u,side=True)}<rect x="270" y="262" width="22" height="386" rx="10" fill="#000" opacity=".25"/></g></svg>')
    # 3. DETAIL (cap + label close-up, 800x1000 with background)
    write(f"{key}-detail.svg", f'<svg xmlns="http://www.w3.org/2000/svg" viewBox="0 0 800 1000" width="800" height="1000">{defs(p,u)}{scene_bg(p,u,800,1000)}<g transform="translate(-200 -60) scale(2)">{bottle(p,u)}</g></svg>')
    # 4. LIFESTYLE
    if key == "nocturne":
        props = ''.join(f'<ellipse cx="{cx}" cy="{cy}" rx="{rx}" ry="{ry}" fill="#7a0c1e" opacity="{o}" transform="rotate({r} {cx} {cy})"/>' for cx,cy,rx,ry,r,o in
            [(190,800,80,46,-20,.9),(250,820,70,40,25,.8),(140,830,64,36,-50,.85),(215,780,50,30,70,.9),(120,790,56,32,10,.7)])
        smoke = ''.join(f'<path d="M{x} 760 C {x-60} 600, {x+70} 480, {x-20} 300 S {x+50} 80, {x} 0" stroke="#e8c9cf" stroke-opacity=".16" stroke-width="{sw}" fill="none" filter="url(#blur{u})"/>' for x,sw in [(520,26),(600,18),(430,22)])
        extra = props + smoke
    else:
        ice = ''.join(f'<rect x="{x}" y="{y}" width="{s}" height="{s}" rx="10" fill="#cfe8ff" opacity=".28" stroke="#fff" stroke-opacity=".5" transform="rotate({r} {x+s/2} {y+s/2})"/>' for x,y,s,r in
            [(120,790,90,12),(250,820,76,-18),(70,850,60,30),(330,780,64,22)])
        frost = ''.join(f'<circle cx="{x}" cy="{y}" r="{r}" fill="#fff" opacity=".5"/>' for x,y,r in [(90,200,3),(660,320,2.5),(560,140,3),(700,600,2),(140,520,2)])
        extra = ice + frost
    write(f"{key}-lifestyle.svg", f'<svg xmlns="http://www.w3.org/2000/svg" viewBox="0 0 800 1000" width="800" height="1000">{defs(p,u)}{scene_bg(p,u,800,1000)}{extra}<g transform="translate(170 170) scale(1.05)">{bottle(p,u)}</g></svg>')
    # 5. FLAT-LAY
    write(f"{key}-flatlay.svg", f'<svg xmlns="http://www.w3.org/2000/svg" viewBox="0 0 1000 800" width="1000" height="800">{defs(p,u)}<defs><linearGradient id="surf{u}" x1="0" y1="0" x2="1" y2="1"><stop offset="0" stop-color="{p["bg1"]}"/><stop offset="1" stop-color="{p["bg2"]}"/></linearGradient></defs><rect width="1000" height="800" fill="url(#surf{u})"/><ellipse cx="500" cy="440" rx="330" ry="40" fill="#000" opacity=".4" filter="url(#soft{u})"/><g transform="translate(130 640) rotate(-90) scale(1)">{bottle(p,u)}</g></svg>')
print("SVG placeholders written to", IMG)

# ───────────────────────── AUDIO ─────────────────────────
SR = 44100
rng = np.random.default_rng(31)

def lp(x, fc, order=4): return signal.sosfilt(signal.butter(order, fc, "low", fs=SR, output="sos"), x)
def bp(x, lo, hi, order=2): return signal.sosfilt(signal.butter(order, [lo, hi], "band", fs=SR, output="sos"), x)
def noise(n): return rng.standard_normal(n)
def seamless(x, fade):
    """make a looping buffer seamless by cross-fading its tail into its head"""
    f = np.linspace(0, 1, fade)
    head, tail = x[:fade].copy(), x[-fade:].copy()
    out = x[:-fade].copy()
    out[:fade] = head * f + tail * (1 - f)
    return out
def norm(x, peak): return x / (np.max(np.abs(x)) + 1e-9) * peak
def tt(n): return np.arange(n) / SR

def save(name, data, kbps, stereo=True, loop=False):
    data = np.clip(data, -1, 1)
    if loop:
        d = data if data.ndim == 1 else data.mean(1)
        print(f"  [seam] {name}: jump {abs(d[0]-d[-1]):.5f} vs typical step {np.abs(np.diff(d)).mean():.5f}")
    if data.ndim == 1: data = np.stack([data, data], 1) if stereo else data[:, None]
    pcm = (data * 32767).astype("<i2")
    with tempfile.NamedTemporaryFile(suffix=".wav", delete=False) as t: wav = t.name
    with wave.open(wav, "wb") as w:
        w.setnchannels(pcm.shape[1]); w.setsampwidth(2); w.setframerate(SR); w.writeframes(pcm.tobytes())
    out = os.path.join(AUD, name)
    subprocess.run(["ffmpeg", "-y", "-loglevel", "error", "-i", wav, "-codec:a", "libmp3lame", "-b:a", f"{kbps}k", out], check=True)
    os.remove(wav)
    print(f"  {name:28s} {os.path.getsize(out)/1024:6.1f} KB")

def stereo_wide(l, r): return np.stack([l, r], 1)

# --- home ambient bed: low drone + wind + faint shimmer (22 s loop)
def ambient_home():
    L = 22; n = SR * (L + 1); t = tt(n)
    drone = sum(a * np.sin(2*np.pi*f*t + ph) for f, a, ph in [(55,.5,0),(82.4,.22,1),(110.3,.12,2),(164.9,.05,.5)])
    drone *= 0.8 + 0.2*np.sin(2*np.pi*(1/L)*t*2)
    wind1 = lp(bp(noise(n), 180, 900), 800) * (0.5 + 0.5*np.sin(2*np.pi*(2/L)*t + .3))
    wind2 = lp(bp(noise(n), 250, 1200), 1000) * (0.5 + 0.5*np.sin(2*np.pi*(3/L)*t + 2))
    shim = sum(np.sin(2*np.pi*f*t)*(0.5+0.5*np.sin(2*np.pi*(k/L)*t+k)) for k,f in enumerate([880, 1318.5, 1760], 1)) * 0.012
    l = drone*.55 + wind1*.9 + shim; r = drone*.55 + wind2*.9 + shim*.8
    l, r = seamless(l, SR), seamless(r, SR)
    m = max(np.max(np.abs(l)), np.max(np.abs(r)))
    return stereo_wide(l/m*.78, r/m*.78)

# --- NOCTURNE: deep drone + slow heartbeat (16 s loop, 10 beats)
def ambient_nocturne():
    L = 16; n = SR*(L+1); t = tt(n)
    drone = sum(a*np.sin(2*np.pi*f*t) for f,a in [(36.7,.6),(73.4,.25),(110.1,.1)]) * (0.8+0.2*np.sin(2*np.pi*(1/L)*t))
    hb = np.zeros(n)
    def thump(pos, amp):
        m = int(.28*SR); tm = np.arange(m)/SR
        env = np.exp(-tm*18) * (1-np.exp(-tm*400))
        s = np.sin(2*np.pi*(52*tm + 30*(1-np.exp(-tm*14))/14*0 )) * env
        hb[pos:pos+m] += lp(s*amp, 160)[:n-pos] if pos+m <= n else (lp(s*amp,160))[:n-pos]
    for b in range(10):
        p0 = int(b*1.6*SR); thump(p0, .9); thump(p0+int(.34*SR), .6)
    warm = lp(bp(noise(n), 90, 500), 450) * (0.6+0.4*np.sin(2*np.pi*(2/L)*t))
    mix = drone*.5 + hb*.75 + warm*.55
    l = seamless(mix, SR); r = seamless(np.roll(mix, 900), SR)
    m = max(abs(l).max(), abs(r).max())
    return stereo_wide(l/m*.78, r/m*.78)

# --- AZUR: cold air + glassy shimmer (20 s loop)
def ambient_azur():
    L = 20; n = SR*(L+1); t = tt(n)
    sweep = 0.5+0.5*np.sin(2*np.pi*(2/L)*t)
    air1 = bp(noise(n), 700, 2600) * (0.25 + 0.75*sweep)
    air2 = bp(noise(n), 600, 3000) * (0.25 + 0.75*(1-sweep))
    glass = sum(np.sin(2*np.pi*f*t + k)*(0.5+0.5*np.sin(2*np.pi*(k/L)*t+k*1.7))**2 for k,f in enumerate([523.3, 784, 1046.5, 1568, 2093], 1))*0.05
    low = np.sin(2*np.pi*98*t)*.25*(0.7+0.3*np.sin(2*np.pi*(1/L)*t))
    l = air1*.6 + glass + low; r = air2*.6 + glass*.9 + low
    l, r = seamless(l, SR), seamless(r, SR)
    m = max(abs(l).max(), abs(r).max())
    return stereo_wide(l/m*.78, r/m*.78)

# --- thunder: crack + long rolling rumble (6 s, mono)
def thunder():
    n = SR*6; t = tt(n)
    crack = bp(noise(n), 300, 6000) * np.exp(-t*14) * (t > 0)
    crack += 0.6*bp(noise(n), 100, 1500) * np.exp(-t*5)
    rumble = lp(noise(n), 140, 4)
    roll = (0.55 + 0.45*np.sin(2*np.pi*3.1*t + np.sin(2*np.pi*.7*t)*2))
    env = (1-np.exp(-t*7)) * np.exp(-t*0.62)
    rumble = rumble * roll * env * 3.2
    sub = lp(noise(n), 60) * env * 4
    x = crack*.9 + rumble + sub*.8
    fade = np.minimum(1, (n-np.arange(n))/(SR*.8))
    return norm(x*fade, .92)

# --- bell: soft inharmonic partials (2.8 s, mono)
def bell():
    n = int(SR*2.8); t = tt(n); x = np.zeros(n)
    for ratio, amp, dec in [(1,1,2.2),(2.76,.5,3.2),(5.4,.28,4.6),(8.93,.14,6),(1.5,.25,2.8)]:
        x += amp*np.sin(2*np.pi*660*ratio*t)*np.exp(-t*dec)
    x *= (1-np.exp(-t*500))
    return norm(x, .8)

print("Audio:")
save("halloween-ambient.mp3", ambient_home(), 56, loop=True)
save("ambient-nocturne.mp3", ambient_nocturne(), 56, loop=True)
save("ambient-azur.mp3", ambient_azur(), 56, loop=True)
save("halloween-thunder.mp3", thunder(), 80, stereo=False)
save("halloween-bell.mp3", bell(), 64, stereo=False)
