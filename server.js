import "dotenv/config";
import express from "express";
import helmet from "helmet";
import rateLimit from "express-rate-limit";
import cookieParser from "cookie-parser";
import bcrypt from "bcryptjs";
import jwt from "jsonwebtoken";
import Database from "better-sqlite3";
import crypto from "crypto";
import Stripe from "stripe";
import path from "path";
import {fileURLToPath} from "url";

const __dirname=path.dirname(fileURLToPath(import.meta.url));
const app=express();
const db=new Database(process.env.DB_PATH||"store.db");
const JWT_SECRET=process.env.JWT_SECRET;
if(!JWT_SECRET || JWT_SECRET==="CHANGE_TO_A_LONG_RANDOM_SECRET") throw new Error("Set a strong JWT_SECRET in .env");

const stripe=process.env.STRIPE_SECRET_KEY ? new Stripe(process.env.STRIPE_SECRET_KEY) : null;

db.pragma("journal_mode = WAL");
db.exec(`
CREATE TABLE IF NOT EXISTS users(
 id INTEGER PRIMARY KEY AUTOINCREMENT,name TEXT NOT NULL,email TEXT UNIQUE NOT NULL,
 password_hash TEXT NOT NULL,role TEXT NOT NULL DEFAULT 'customer',
 created_at TEXT NOT NULL
);
CREATE TABLE IF NOT EXISTS products(
 id INTEGER PRIMARY KEY AUTOINCREMENT,name TEXT NOT NULL,slug TEXT UNIQUE NOT NULL,
 category TEXT NOT NULL,price REAL NOT NULL,currency TEXT NOT NULL DEFAULT 'TRY',
 stock INTEGER NOT NULL DEFAULT 0,description TEXT NOT NULL DEFAULT '',
 image TEXT NOT NULL DEFAULT '',active INTEGER NOT NULL DEFAULT 1,created_at TEXT NOT NULL
);
CREATE TABLE IF NOT EXISTS orders(
 id TEXT PRIMARY KEY,user_id INTEGER,name TEXT NOT NULL,email TEXT NOT NULL,phone TEXT NOT NULL,
 address TEXT NOT NULL DEFAULT '',total REAL NOT NULL,currency TEXT NOT NULL,
 items_json TEXT NOT NULL,status TEXT NOT NULL DEFAULT 'pending',
 payment_status TEXT NOT NULL DEFAULT 'unpaid',payment_ref TEXT,
 created_at TEXT NOT NULL,updated_at TEXT NOT NULL
);
CREATE TABLE IF NOT EXISTS coupons(
 id INTEGER PRIMARY KEY AUTOINCREMENT,code TEXT UNIQUE NOT NULL,
 type TEXT NOT NULL DEFAULT 'percent',value REAL NOT NULL,
 min_total REAL NOT NULL DEFAULT 0,active INTEGER NOT NULL DEFAULT 1,
 expires_at TEXT
);
CREATE TABLE IF NOT EXISTS settings(key TEXT PRIMARY KEY,value TEXT NOT NULL);
`);

const now=()=>new Date().toISOString();
const slugify=s=>s.toString().trim().toLowerCase().replace(/[^a-z0-9\u0600-\u06ff]+/g,"-").replace(/^-|-$/g,"");
function tokenFor(u){return jwt.sign({id:u.id,name:u.name,email:u.email,role:u.role},JWT_SECRET,{expiresIn:"7d"});}
function auth(req,res,next){try{const t=req.cookies.auth;if(!t)return res.status(401).json({error:"غير مسجل الدخول"});req.user=jwt.verify(t,JWT_SECRET);next()}catch{res.status(401).json({error:"انتهت الجلسة"})}}
function admin(req,res,next){if(req.user?.role!=="admin")return res.status(403).json({error:"صلاحية المدير مطلوبة"});next()}
const emailOK=e=>/^[^\s@]+@[^\s@]+\.[^\s@]+$/.test(e||"");
const safeUser=u=>({id:u.id,name:u.name,email:u.email,role:u.role});

const seed=db.prepare("SELECT COUNT(*) c FROM products").get().c;
if(!seed){
 const add=db.prepare("INSERT INTO products(name,slug,category,price,currency,stock,description,image,created_at) VALUES(?,?,?,?,?,?,?,?,?)");
 [
  ["Google Play تركيا","google-play-turkey","البطاقات",100,"TRY",50,"بطاقة رقمية","🎁"],
  ["Apple Gift Card","apple-gift-card","البطاقات",150,"TRY",50,"بطاقة رقمية","🍎"],
  ["Steam Gift Card","steam-gift-card","البطاقات",200,"TRY",40,"بطاقة ألعاب","🎮"],
  ["Game Credits","game-credits","الألعاب",75,"TRY",100,"رصيد ألعاب","🕹️"],
  ["اشتراك مشاهدة","stream-subscription","الاشتراكات",120,"TRY",30,"اشتراك رقمي","📺"],
  ["تفعيل برامج","software-activation","البرامج",180,"TRY",25,"ترخيص قانوني","💻"],
  ["تطبيقات رقمية","digital-apps","التطبيقات",90,"TRY",40,"خدمة رقمية","📱"],
  ["حوالة رقمية","money-transfer","الحوالات",50,"TRY",20,"خدمة تجريبية","💸"]
 ].forEach(x=>add.run(...x,now()));
}
if(process.env.ADMIN_EMAIL && process.env.ADMIN_PASSWORD){
 const exists=db.prepare("SELECT id FROM users WHERE email=?").get(process.env.ADMIN_EMAIL.toLowerCase());
 if(!exists){
  const hash=bcrypt.hashSync(process.env.ADMIN_PASSWORD,12);
  db.prepare("INSERT INTO users(name,email,password_hash,role,created_at) VALUES(?,?,?,?,?)")
    .run(process.env.ADMIN_NAME||"Admin",process.env.ADMIN_EMAIL.toLowerCase(),hash,"admin",now());
  console.log("Initial admin created:",process.env.ADMIN_EMAIL);
 }
}

app.use(helmet({contentSecurityPolicy:false}));
app.use(cookieParser());
app.use(express.json({limit:"100kb"}));
app.use(rateLimit({windowMs:15*60*1000,max:500,standardHeaders:true,legacyHeaders:false}));
app.use(express.static(path.join(__dirname,"public")));

app.get("/api/config",(req,res)=>res.json({payments:!!stripe,currency:"TRY"}));
app.get("/api/categories",(req,res)=>res.json(db.prepare("SELECT DISTINCT category FROM products WHERE active=1 ORDER BY category").all().map(x=>x.category)));
app.get("/api/products",(req,res)=>{
 const q=(req.query.q||"").trim(),cat=(req.query.category||"").trim();
 let sql="SELECT id,name,slug,category,price,currency,stock,description,image FROM products WHERE active=1",p=[];
 if(q){sql+=" AND (name LIKE ? OR description LIKE ?)";p.push(`%${q}%`,`%${q}%`)}
 if(cat&&cat!=="الكل"){sql+=" AND category=?";p.push(cat)}
 res.json(db.prepare(sql+" ORDER BY id DESC").all(...p));
});

app.post("/api/register",async(req,res)=>{
 const {name,email,password}=req.body;
 if(!name||!emailOK(email)||typeof password!=="string"||password.length<8)return res.status(400).json({error:"أدخل بيانات صحيحة وكلمة مرور من 8 أحرف على الأقل"});
 try{
  const hash=await bcrypt.hash(password,12);
  const r=db.prepare("INSERT INTO users(name,email,password_hash,created_at) VALUES(?,?,?,?)").run(name,email.toLowerCase(),hash,now());
  const u=db.prepare("SELECT * FROM users WHERE id=?").get(r.lastInsertRowid);
  res.cookie("auth",tokenFor(u),{httpOnly:true,sameSite:"lax",secure:process.env.NODE_ENV==="production",maxAge:7*864e5});
  res.json({user:safeUser(u)});
 }catch{res.status(409).json({error:"البريد مستخدم مسبقاً"})}
});
app.post("/api/login",async(req,res)=>{
 const u=db.prepare("SELECT * FROM users WHERE email=?").get((req.body.email||"").toLowerCase());
 if(!u||!(await bcrypt.compare(req.body.password||"",u.password_hash)))return res.status(401).json({error:"بيانات الدخول غير صحيحة"});
 res.cookie("auth",tokenFor(u),{httpOnly:true,sameSite:"lax",secure:process.env.NODE_ENV==="production",maxAge:7*864e5});
 res.json({user:safeUser(u)});
});
app.post("/api/logout",(req,res)=>{res.clearCookie("auth");res.json({ok:true})});
app.get("/api/me",auth,(req,res)=>res.json({user:req.user}));

app.post("/api/coupons/check",(req,res)=>{
 const code=(req.body.code||"").trim().toUpperCase();
 const c=db.prepare("SELECT * FROM coupons WHERE code=? AND active=1").get(code);
 if(!c || (c.expires_at && c.expires_at<now()))return res.status(404).json({error:"الكوبون غير صالح"});
 const subtotal=Number(req.body.subtotal||0);
 if(subtotal<c.min_total)return res.status(400).json({error:`الحد الأدنى ${c.min_total}`});
 const discount=c.type==="percent"?Math.min(subtotal,subtotal*c.value/100):Math.min(subtotal,c.value);
 res.json({code:c.code,discount,total:subtotal-discount});
});

function validateItems(items){
 if(!Array.isArray(items)||!items.length)throw Error("السلة فارغة");
 const get=db.prepare("SELECT id,name,price,currency,stock,active FROM products WHERE id=?");
 const normalized=[];let total=0,currency="TRY";
 for(const raw of items){
  const p=get.get(Number(raw.id)),qty=Math.floor(Number(raw.qty));
  if(!p||!p.active||qty<1||qty>100||p.stock<qty)throw Error(`المنتج غير متوفر: ${p?.name||raw.id}`);
  total+=p.price*qty;currency=p.currency;
  normalized.push({id:p.id,name:p.name,price:p.price,qty});
 }
 return {normalized,total,currency};
}

app.post("/api/orders",auth,(req,res)=>{
 try{
  const {name,email,phone,address="",items,couponCode}=req.body;
  if(!name||!emailOK(email)||!phone)return res.status(400).json({error:"بيانات العميل غير مكتملة"});
  let {normalized,total,currency}=validateItems(items);
  if(couponCode){
   const c=db.prepare("SELECT * FROM coupons WHERE code=? AND active=1").get(couponCode.toUpperCase());
   if(c && (!c.expires_at||c.expires_at>=now())){
    const d=c.type==="percent"?Math.min(total,total*c.value/100):Math.min(total,c.value);
    total-=d;
   }
  }
  const id="ORD-"+crypto.randomBytes(6).toString("hex").toUpperCase();
  const tx=db.transaction(()=>{
   db.prepare("INSERT INTO orders(id,user_id,name,email,phone,address,total,currency,items_json,status,payment_status,created_at,updated_at) VALUES(?,?,?,?,?,?,?,?,?,?,?,?,?)")
   .run(id,req.user.id,name,email,phone,address,total,currency,JSON.stringify(normalized),"pending","unpaid",now(),now());
   for(const x of normalized)db.prepare("UPDATE products SET stock=stock-? WHERE id=?").run(x.qty,x.id);
  });
  tx();
  res.json({order:{id,total,currency,status:"pending",payment_status:"unpaid"}});
 }catch(e){res.status(400).json({error:e.message})}
});

app.post("/api/checkout",auth,async(req,res)=>{
 if(!stripe)return res.status(503).json({error:"بوابة الدفع غير مفعلة. أضف STRIPE_SECRET_KEY في .env"});
 try{
  const order=db.prepare("SELECT * FROM orders WHERE id=? AND user_id=?").get(req.body.orderId,req.user.id);
  if(!order)return res.status(404).json({error:"الطلب غير موجود"});
  const items=JSON.parse(order.items_json);
  const session=await stripe.checkout.sessions.create({
   mode:"payment",
   customer_email:order.email,
   line_items:items.map(x=>({price_data:{currency:order.currency.toLowerCase(),product_data:{name:x.name},unit_amount:Math.round(x.price*100)},quantity:x.qty})),
   metadata:{order_id:order.id},
   success_url:`${process.env.PUBLIC_URL||"http://localhost:3000"}/?paid=1&order=${order.id}`,
   cancel_url:`${process.env.PUBLIC_URL||"http://localhost:3000"}/?cancelled=1&order=${order.id}`
  });
  db.prepare("UPDATE orders SET payment_ref=?,updated_at=? WHERE id=?").run(session.id,now(),order.id);
  res.json({url:session.url});
 }catch(e){res.status(500).json({error:"تعذر إنشاء جلسة الدفع"})}
});

app.post("/api/stripe/webhook",express.raw({type:"application/json"}),async(req,res)=>{
 if(!stripe||!process.env.STRIPE_WEBHOOK_SECRET)return res.status(503).send("Webhook not configured");
 let event;try{event=stripe.webhooks.constructEvent(req.body,req.headers["stripe-signature"],process.env.STRIPE_WEBHOOK_SECRET)}catch(e){return res.status(400).send("Invalid signature")}
 if(event.type==="checkout.session.completed"){
  const s=event.data.object,o=db.prepare("SELECT * FROM orders WHERE id=?").get(s.metadata?.order_id);
  if(o)db.prepare("UPDATE orders SET status='paid',payment_status='paid',updated_at=? WHERE id=?").run(now(),o.id);
 }
 res.json({received:true});
});

app.get("/api/orders",auth,(req,res)=>res.json(db.prepare("SELECT id,total,currency,status,payment_status,created_at,items_json FROM orders WHERE user_id=? ORDER BY created_at DESC").all(req.user.id)));

app.get("/api/admin/stats",auth,admin,(req,res)=>res.json({
 users:db.prepare("SELECT COUNT(*) c FROM users").get().c,
 products:db.prepare("SELECT COUNT(*) c FROM products").get().c,
 orders:db.prepare("SELECT COUNT(*) c FROM orders").get().c,
 sales:db.prepare("SELECT COALESCE(SUM(total),0) s FROM orders WHERE payment_status='paid'").get().s
}));
app.get("/api/admin/products",auth,admin,(req,res)=>res.json(db.prepare("SELECT * FROM products ORDER BY id DESC").all()));
app.post("/api/admin/products",auth,admin,(req,res)=>{
 const {name,category,price,currency="TRY",stock=0,description="",image="💎"}=req.body;
 if(!name||!category||!Number.isFinite(Number(price))||Number(price)<0)return res.status(400).json({error:"بيانات المنتج غير صحيحة"});
 let slug=slugify(name); if(db.prepare("SELECT id FROM products WHERE slug=?").get(slug))slug+= "-"+Date.now();
 const r=db.prepare("INSERT INTO products(name,slug,category,price,currency,stock,description,image,created_at) VALUES(?,?,?,?,?,?,?,?,?)")
 .run(name,slug,category,Number(price),currency,Math.max(0,Math.floor(stock)),description,image,now());
 res.json(db.prepare("SELECT * FROM products WHERE id=?").get(r.lastInsertRowid));
});
app.patch("/api/admin/products/:id",auth,admin,(req,res)=>{
 const p=db.prepare("SELECT * FROM products WHERE id=?").get(req.params.id);if(!p)return res.status(404).json({error:"غير موجود"});
 const n={...p,...req.body};
 db.prepare("UPDATE products SET name=?,category=?,price=?,currency=?,stock=?,description=?,image=?,active=? WHERE id=?")
 .run(n.name,n.category,Number(n.price),n.currency,Math.max(0,Math.floor(n.stock)),n.description,n.image,n.active?1:0,p.id);
 res.json({ok:true});
});
app.get("/api/admin/orders",auth,admin,(req,res)=>res.json(db.prepare("SELECT * FROM orders ORDER BY created_at DESC").all()));
app.patch("/api/admin/orders/:id",auth,admin,(req,res)=>{
 const allowed=["pending","paid","processing","completed","cancelled"];
 if(!allowed.includes(req.body.status))return res.status(400).json({error:"حالة غير صحيحة"});
 db.prepare("UPDATE orders SET status=?,updated_at=? WHERE id=?").run(req.body.status,now(),req.params.id);res.json({ok:true});
});
app.post("/api/admin/coupons",auth,admin,(req,res)=>{
 const {code,type="percent",value,min_total=0,expires_at=null}=req.body;
 if(!code||!["percent","fixed"].includes(type)||Number(value)<=0)return res.status(400).json({error:"بيانات الكوبون غير صحيحة"});
 try{db.prepare("INSERT INTO coupons(code,type,value,min_total,expires_at) VALUES(?,?,?,?,?)").run(code.toUpperCase(),type,Number(value),Number(min_total),expires_at||null);res.json({ok:true})}
 catch{res.status(409).json({error:"الكود مستخدم"})}
});
app.get("/api/admin/coupons",auth,admin,(req,res)=>res.json(db.prepare("SELECT * FROM coupons ORDER BY id DESC").all()));

app.get("*",(req,res)=>res.sendFile(path.join(__dirname,"public","index.html")));
const port=process.env.PORT||3000;
app.listen(port,()=>console.log(`Store: http://localhost:${port}`));
