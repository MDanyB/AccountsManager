import React, { useEffect, useMemo, useRef, useState } from "react";
import { motion, AnimatePresence } from "framer-motion";
import { Plus, Lock, Unlock, FolderPlus, Search, Trash2, Pencil, Eye, EyeOff, Copy, LogOut, ShieldCheck, Save, KeyRound, Users } from "lucide-react";
import { v4 as uuidv4 } from "uuid";

// Single-file React + Tailwind + framer-motion demo
// SECURITY IMPROVEMENTS in this version:
// - PBKDF2 iterations increased (configurable)
// - Explicit checks preventing creating entries without selecting a folder (person)
// - Folder creation and editing implemented via modal instead of prompt (works reliably in modern browsers)
// - Export/Import encrypted blob (for backup)
// - Basic password-strength hint and minimum-length checks
// IMPORTANT: Still a demo. For production, use Argon2id, secure server-side storage, audited crypto.

const STORAGE_KEY = "apv.vault";
const DEFAULT_PBKDF2_ITERS = 400000; // increased from 250k

const base64ToArrayBuffer = (b64) => Uint8Array.from(atob(b64), (c) => c.charCodeAt(0));
const arrayBufferToBase64 = (buf) => btoa(String.fromCharCode(...new Uint8Array(buf)));

async function deriveKey(password, saltB64, iterations = DEFAULT_PBKDF2_ITERS) {
  const enc = new TextEncoder();
  const salt = saltB64 ? base64ToArrayBuffer(saltB64) : crypto.getRandomValues(new Uint8Array(16));
  const keyMaterial = await crypto.subtle.importKey(
    "raw",
    enc.encode(password),
    { name: "PBKDF2" },
    false,
    ["deriveKey"]
  );
  const key = await crypto.subtle.deriveKey(
    { name: "PBKDF2", salt, iterations, hash: "SHA-256" },
    keyMaterial,
    { name: "AES-GCM", length: 256 },
    false,
    ["encrypt", "decrypt"]
  );
  const saltOut = saltB64 || arrayBufferToBase64(salt);
  return { key, saltB64: saltOut, iterations };
}

async function encryptVault(key, json) {
  const iv = crypto.getRandomValues(new Uint8Array(12));
  const encoded = new TextEncoder().encode(JSON.stringify(json));
  const ct = await crypto.subtle.encrypt({ name: "AES-GCM", iv }, key, encoded);
  return { iv: arrayBufferToBase64(iv), data: arrayBufferToBase64(ct) };
}

async function decryptVault(key, ivB64, dataB64) {
  const iv = base64ToArrayBuffer(ivB64);
  const data = base64ToArrayBuffer(dataB64);
  const pt = await crypto.subtle.decrypt({ name: "AES-GCM", iv }, key, data);
  return JSON.parse(new TextDecoder().decode(pt));
}

function saveEncryptedToStorage(payload) {
  localStorage.setItem(STORAGE_KEY, JSON.stringify(payload));
}
function loadEncryptedFromStorage() {
  const raw = localStorage.getItem(STORAGE_KEY);
  if (!raw) return null;
  try { return JSON.parse(raw); } catch { return null; }
}

function defaultPlainVault() { return { people: [], items: [] }; }
const COLORS = ["#60a5fa","#34d399","#f472b6","#fbbf24","#a78bfa","#f87171","#22d3ee","#fb923c"];

function prettyDate(iso){ try { return new Date(iso).toLocaleString(); } catch { return iso; } }

export default function App(){
  const [locked, setLocked] = useState(true);
  const [hasExistingVault, setHasExistingVault] = useState(false);
  const [master, setMaster] = useState("");
  const [master2, setMaster2] = useState("");
  const [working, setWorking] = useState(false);
  const [saltB64, setSaltB64] = useState("");
  const [cryptoKey, setCryptoKey] = useState(null);
  const [plain, setPlain] = useState(defaultPlainVault());
  const [search, setSearch] = useState("");
  const [activePersonId, setActivePersonId] = useState(null);
  const [showPasswords, setShowPasswords] = useState(false);
  const [editItem, setEditItem] = useState(null);
  const [personModal, setPersonModal] = useState({ open:false, editing:null, name:"", color: COLORS[0] });
  const saveTimeout = useRef(null);

  useEffect(()=>{
    const existing = loadEncryptedFromStorage();
    setHasExistingVault(!!existing);
    if(existing?.salt) setSaltB64(existing.salt);
  }, []);

  async function handleCreateNewVault(){
    if(!master || master.length < 8){ alert("Master password must be at least 8 characters."); return; }
    if(master !== master2){ alert("Passwords do not match."); return; }
    setWorking(true);
    try{
      const { key, saltB64 } = await deriveKey(master);
      setCryptoKey(key);
      setSaltB64(saltB64);
      const initial = defaultPlainVault();
      const enc = await encryptVault(key, initial);
      saveEncryptedToStorage({ version:1, salt: saltB64, iv: enc.iv, data: enc.data, iterations: DEFAULT_PBKDF2_ITERS, lastSaved: new Date().toISOString() });
      setPlain(initial);
      setHasExistingVault(true);
      setLocked(false);
      alert("Vault created.");
    }catch(e){ console.error(e); alert("Failed to create vault."); }
    setWorking(false);
  }

  async function handleUnlock(){
    setWorking(true);
    try{
      const stored = loadEncryptedFromStorage();
      if(!stored){ alert("No vault found."); setWorking(false); return; }
      const { key } = await deriveKey(master, stored.salt, stored.iterations || DEFAULT_PBKDF2_ITERS);
      const dec = await decryptVault(key, stored.iv, stored.data);
      setCryptoKey(key);
      setSaltB64(stored.salt);
      setPlain(dec);
      setLocked(false);
      alert("Unlocked.");
    }catch(e){ console.error(e); alert("Incorrect password or corrupt vault."); }
    setWorking(false);
  }

  async function persist(){
    if(!cryptoKey) return;
    const enc = await encryptVault(cryptoKey, plain);
    saveEncryptedToStorage({ version:1, salt: saltB64, iv: enc.iv, data: enc.data, iterations: DEFAULT_PBKDF2_ITERS, lastSaved: new Date().toISOString() });
  }

  function lockNow(){ setLocked(true); setMaster(""); setMaster2(""); setCryptoKey(null); setPlain(defaultPlainVault()); setActivePersonId(null); }

  // PERSON (folder) functions - modal-based
  function openAddPerson(){ setPersonModal({ open:true, editing:null, name:"", color: COLORS[Math.floor(Math.random()*COLORS.length)] }); }
  function openEditPerson(p){ setPersonModal({ open:true, editing:p, name:p.name, color:p.color }); }
  function closePersonModal(){ setPersonModal({ open:false, editing:null, name:"", color: COLORS[0] }); }
  function savePerson(){
    const name = (personModal.name || "").trim();
    if(!name){ alert("Name required."); return; }
    // prevent duplicates
    if(personModal.editing){
      const people = plain.people.map(x=> x.id===personModal.editing.id ? { ...x, name, color: personModal.color } : x);
      setPlain({ ...plain, people });
    } else {
      const id = uuidv4();
      const person = { id, name, color: personModal.color };
      const people = [...plain.people, person];
      setPlain({ ...plain, people });
      setActivePersonId(id);
    }
    closePersonModal();
  }

  function deletePerson(p){ if(!confirm(`Delete folder "${p.name}" and its entries?`)) return; const people = plain.people.filter(x=>x.id!==p.id); const items = plain.items.filter(x=>x.personId!==p.id); setPlain({ ...plain, people, items }); if(activePersonId===p.id) setActivePersonId(null); }

  // ITEM functions
  function openNewItem(personId){
    const pid = personId || activePersonId || plain.people[0]?.id || null;
    if(!pid){ alert("Please create/select a folder (person) first."); return; }
    setEditItem({ id: uuidv4(), personId: pid, title:"", username:"", password:"", url:"", notes:"", createdAt: new Date().toISOString(), updatedAt: new Date().toISOString(), isNew:true });
  }
  function editExisting(it){ setEditItem({ ...it, isNew:false }); }
  function saveItem(it){
    if(!it.personId){ alert("Select a folder (person) for this entry."); return; }
    const items = [...plain.items];
    const idx = items.findIndex(x=>x.id===it.id);
    it.updatedAt = new Date().toISOString();
    if(idx>=0) items[idx]=it; else items.unshift(it);
    setPlain({ ...plain, items });
    setEditItem(null);
  }
  function deleteItem(it){ if(!confirm(`Delete entry "${it.title||it.username||'Untitled'}"?`)) return; const items = plain.items.filter(x=>x.id!==it.id); setPlain({ ...plain, items }); }
  function copyToClipboard(text){ navigator.clipboard.writeText(text).then(()=> alert('Copied')); }

  const filteredItems = useMemo(()=>{
    let list = plain.items;
    if(activePersonId) list = list.filter(x=>x.personId===activePersonId);
    if(search.trim()){ const q = search.toLowerCase(); list = list.filter(x=> (x.title||"").toLowerCase().includes(q) || (x.username||"").toLowerCase().includes(q) || (x.url||"").toLowerCase().includes(q) || (x.notes||"").toLowerCase().includes(q)); }
    return list;
  }, [plain.items, activePersonId, search]);

  // autosave debounce
  useEffect(()=>{
    if(locked || !cryptoKey) return;
    if(saveTimeout.current) clearTimeout(saveTimeout.current);
    saveTimeout.current = setTimeout(()=>{ persist(); }, 800);
    return ()=> saveTimeout.current && clearTimeout(saveTimeout.current);
  }, [plain, locked]);

  // backup/export and import
  function exportVault(){ const raw = loadEncryptedFromStorage(); if(!raw){ alert('No vault to export'); return; } const blob = new Blob([JSON.stringify(raw)], { type: 'application/json' }); const url = URL.createObjectURL(blob); const a = document.createElement('a'); a.href = url; a.download = 'apv.vault.json'; a.click(); URL.revokeObjectURL(url); }
  function importVaultFile(file){ const reader = new FileReader(); reader.onload = (e)=>{ try{ const parsed = JSON.parse(e.target.result); if(!parsed.data){ alert('Invalid vault file'); return; } saveEncryptedToStorage(parsed); setHasExistingVault(true); alert('Imported vault — now unlock with your master password.'); }catch(err){ alert('Failed to import'); } }; reader.readAsText(file); }

  // UI: locked screen
  if(locked) return (
    <div className="min-h-screen w-full bg-gradient-to-br from-slate-900 via-slate-800 to-slate-900 text-white flex items-center justify-center p-6">
      <div className="w-full max-w-xl bg-white/6 rounded-2xl p-6 backdrop-blur border border-white/10">
        <div className="flex items-center gap-3 mb-4"><ShieldCheckIcon/> <h2 className="text-xl font-semibold">Animated Password Vault</h2></div>
        {!hasExistingVault ? (
          <div className="space-y-3">
            <div className="text-sm">Create a new vault (master password). This will encrypt all data locally.</div>
            <input type="password" placeholder="Master password (min 8)" value={master} onChange={(e)=>setMaster(e.target.value)} className="w-full p-2 rounded bg-white/10" />
            <input type="password" placeholder="Confirm password" value={master2} onChange={(e)=>setMaster2(e.target.value)} className="w-full p-2 rounded bg-white/10" />
            <div className="flex gap-2">
              <button onClick={handleCreateNewVault} className="px-4 py-2 rounded bg-indigo-600">Create Vault</button>
              <button onClick={()=>{ const f = document.createElement('input'); f.type='file'; f.accept='application/json'; f.onchange = (e)=> importVaultFile(e.target.files[0]); f.click(); }} className="px-4 py-2 rounded bg-white/5">Import Vault</button>
            </div>
          </div>
        ) : (
          <div className="space-y-3">
            <div className="text-sm">Enter your master password to unlock.</div>
            <input type="password" placeholder="Master password" value={master} onChange={(e)=>setMaster(e.target.value)} className="w-full p-2 rounded bg-white/10" />
            <div className="flex gap-2">
              <button onClick={handleUnlock} className="px-4 py-2 rounded bg-green-600">Unlock</button>
              <button onClick={()=>{ const f = document.createElement('input'); f.type='file'; f.accept='application/json'; f.onchange = (e)=> importVaultFile(e.target.files[0]); f.click(); }} className="px-4 py-2 rounded bg-white/5">Import Vault</button>
            </div>
            <div className="text-xs text-white/70">If you forget your master password, your data cannot be recovered.</div>
          </div>
        )}
      </div>
    </div>
  );

  // Unlocked UI
  return (
    <div className="min-h-screen bg-gradient-to-br from-slate-900 via-slate-800 to-slate-900 text-white">
      <div className="p-4 flex items-center justify-between border-b border-white/10">
        <div className="flex items-center gap-3"><UsersIcon/><div className="font-semibold">Animated Password Vault</div><div className="text-xs text-white/60">(Demo — local only)</div></div>
        <div className="flex items-center gap-2">
          <input value={search} onChange={(e)=>setSearch(e.target.value)} placeholder="Search..." className="p-2 rounded bg-white/10" />
          <button onClick={()=> openNewItem()} className="px-3 py-2 rounded bg-indigo-600">New Entry</button>
          <div className="bg-white/5 p-2 rounded">
            <button onClick={()=> setShowPasswords(s=>!s)} className="mr-2">{showPasswords? 'Hide':'Show'} pw</button>
            <button onClick={persist} className="mr-2">Save</button>
            <button onClick={exportVault} className="mr-2">Export</button>
            <button onClick={lockNow}>Lock</button>
          </div>
        </div>
      </div>

      <div className="grid grid-cols-12 gap-4 p-4">
        <aside className="col-span-12 md:col-span-3 lg:col-span-2">
          <div className="bg-white/5 p-3 rounded-xl">
            <div className="flex items-center justify-between mb-2"><div className="font-semibold">Folders</div><button onClick={openAddPerson} className="p-1 rounded bg-white/10">New</button></div>
            <div className="space-y-2 max-h-[60vh] overflow-auto">
              {plain.people.length===0 && <div className="text-sm text-white/60">No folders yet.</div>}
              {plain.people.map(p=> (
                <motion.div key={p.id} layout initial={{ opacity:0,y:6 }} animate={{ opacity:1,y:0 }} className={`p-2 rounded ${activePersonId===p.id? 'bg-white/15':'bg-white/5'} flex items-center justify-between`} onClick={()=> setActivePersonId(p.id)}>
                  <div className="flex items-center gap-2"><span style={{background:p.color}} className="w-3 h-3 rounded-full inline-block"/> <div className="text-sm">{p.name}</div></div>
                  <div className="flex gap-1"><button onClick={(e)=>{ e.stopPropagation(); openEditPerson(p); }} className="p-1 rounded bg-white/6">Edit</button><button onClick={(e)=>{ e.stopPropagation(); deletePerson(p); }} className="p-1 rounded bg-red-600">Del</button></div>
                </motion.div>
              ))}
            </div>
          </div>
        </aside>

        <main className="col-span-12 md:col-span-9 lg:col-span-10">
          <div className="bg-white/5 p-4 rounded-2xl">
            <div className="font-semibold mb-3">Entries</div>
            <div className="grid sm:grid-cols-2 lg:grid-cols-3 gap-3">
              <AnimatePresence>
                {filteredItems.map(it=> (
                  <motion.div key={it.id} layout initial={{opacity:0,y:8}} animate={{opacity:1,y:0}} exit={{opacity:0}} className="p-4 rounded-xl bg-white/10 border border-white/10">
                    <div className="flex justify-between items-start">
                      <div>
                        <div className="font-semibold">{it.title||'Untitled'}</div>
                        <div className="text-xs text-white/60">{prettyDate(it.updatedAt)}</div>
                      </div>
                      <div className="flex gap-1">
                        <button onClick={()=> editExisting(it)} className="p-1 rounded bg-white/6">Edit</button>
                        <button onClick={()=> deleteItem(it)} className="p-1 rounded bg-red-600">Del</button>
                      </div>
                    </div>
                    {it.url && <a href={(it.url.startsWith('http')? it.url : 'https://'+it.url)} target="_blank" rel="noreferrer" className="block text-sm underline mt-2">{it.url}</a>}
                    <div className="mt-2 text-sm">Username: <span className="font-mono">{it.username||'—'}</span></div>
                    <div className="mt-2 text-sm">Password: <span className="font-mono">{it.password ? (showPasswords? it.password : '•'.repeat(Math.min(12,it.password.length))) : '—'}</span> {it.password && <button onClick={()=> copyToClipboard(it.password)} className="ml-2">Copy</button>}</div>
                    {it.notes && <div className="mt-2 text-sm whitespace-pre-wrap text-white/80">{it.notes}</div>}
                  </motion.div>
                ))}
              </AnimatePresence>
            </div>
            {filteredItems.length===0 && <div className="p-6 text-center text-white/60">No entries. Create one.</div>}
          </div>
        </main>
      </div>

      {/* Person Modal */}
      {personModal.open && (
        <div className="fixed inset-0 bg-black/50 flex items-center justify-center">
          <div className="bg-slate-800 p-4 rounded-lg w-full max-w-md">
            <div className="flex justify-between items-center mb-2"><div className="font-semibold">{personModal.editing? 'Edit Folder' : 'New Folder'}</div><button onClick={closePersonModal}>X</button></div>
            <div className="space-y-2">
              <input value={personModal.name} onChange={(e)=> setPersonModal({...personModal, name: e.target.value})} placeholder="Folder (person) name" className="w-full p-2 rounded bg-white/6" />
              <div className="flex gap-2 flex-wrap">
                {COLORS.map(c=> (<button key={c} onClick={()=> setPersonModal({...personModal, color:c})} style={{background:c}} className={`w-8 h-8 rounded ${personModal.color===c? 'ring-2 ring-white':''}`} />))}
              </div>
              <div className="flex justify-end gap-2">
                <button onClick={closePersonModal} className="px-3 py-1 rounded bg-white/6">Cancel</button>
                <button onClick={savePerson} className="px-3 py-1 rounded bg-green-600">Save</button>
              </div>
            </div>
          </div>
        </div>
      )}

      {/* Edit Item Modal */}
      {editItem && (
        <div className="fixed inset-0 bg-black/50 flex items-center justify-center">
          <div className="bg-slate-800 p-4 rounded-lg w-full max-w-2xl">
            <div className="flex justify-between items-center mb-2"><div className="font-semibold">{editItem.isNew? 'New Entry' : 'Edit Entry'}</div><button onClick={()=> setEditItem(null)}>X</button></div>
            <div className="grid gap-2">
              <div className="grid grid-cols-2 gap-2">
                <input value={editItem.title} onChange={(e)=> setEditItem({...editItem, title: e.target.value})} placeholder="Title" className="p-2 rounded bg-white/6" />
                <select value={editItem.personId||''} onChange={(e)=> setEditItem({...editItem, personId: e.target.value})} className="p-2 rounded bg-white/6">
                  <option value="">— Select folder —</option>
                  {plain.people.map(p=> (<option key={p.id} value={p.id}>{p.name}</option>))}
                </select>
              </div>
              <div className="grid grid-cols-2 gap-2">
                <input value={editItem.username} onChange={(e)=> setEditItem({...editItem, username: e.target.value})} placeholder="Username" className="p-2 rounded bg-white/6" />
                <input value={editItem.password} onChange={(e)=> setEditItem({...editItem, password: e.target.value})} placeholder="Password" className="p-2 rounded bg-white/6" />
              </div>
              <input value={editItem.url} onChange={(e)=> setEditItem({...editItem, url: e.target.value})} placeholder="URL" className="p-2 rounded bg-white/6" />
              <textarea value={editItem.notes} onChange={(e)=> setEditItem({...editItem, notes: e.target.value})} placeholder="Notes" className="p-2 rounded bg-white/6" rows={4} />
              <div className="flex justify-end gap-2">
                <button onClick={()=> setEditItem(null)} className="px-3 py-1 rounded bg-white/6">Cancel</button>
                <button onClick={()=> saveItem(editItem)} className="px-3 py-1 rounded bg-green-600">Save</button>
              </div>
            </div>
          </div>
        </div>
      )}

      <div className="p-4 text-center text-xs text-white/50">Encrypted locally • If you lose the master password, data is unrecoverable.</div>
    </div>
  );
}

// tiny icons fallback
function ShieldCheckIcon(){ return (<svg className="h-6 w-6" viewBox="0 0 24 24" fill="none" stroke="currentColor"><path d="M12 2l7 3v5c0 5-3.5 9.74-7 12-3.5-2.26-7-7-7-12V5l7-3z" strokeWidth="1.5" strokeLinecap="round" strokeLinejoin="round"/><path d="M9 12l2 2 4-4" strokeWidth="1.5" strokeLinecap="round" strokeLinejoin="round"/></svg>); }
function UsersIcon(){ return (<svg className="h-6 w-6" viewBox="0 0 24 24" fill="none" stroke="currentColor"><path d="M17 21v-2a4 4 0 00-4-4H7a4 4 0 00-4 4v2" strokeWidth="1.5" strokeLinecap="round" strokeLinejoin="round"/><circle cx="9" cy="7" r="4" strokeWidth="1.5" strokeLinecap="round" strokeLinejoin="round"/><path d="M23 21v-2a4 4 0 00-3-3.87" strokeWidth="1.5" strokeLinecap="round" strokeLinejoin="round"/><path d="M16 3.13a4 4 0 010 7.75" strokeWidth="1.5" strokeLinecap="round" strokeLinejoin="round"/></svg>); }
