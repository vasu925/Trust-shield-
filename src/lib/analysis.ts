export type Finding = {label:string;detail:string;severity:'high'|'medium'|'low'};
export type Scan = {id:string;kind:'URL'|'MESSAGE'|'PRODUCT';target:string;score:number;level:'HIGH'|'MEDIUM'|'LOW';date:string;findings:Finding[]};
const urgent = ['urgent','immediately','suspended','verify now','act now','limited time','account blocked','final warning'];
const credential = ['otp','password','pin','cvv','bank details','login details','one-time password'];
const money = ['gift card','wire transfer','crypto','upi payment','advance fee','processing fee'];
export function analyzeMessage(text:string): Scan {
 const t=text.toLowerCase(); const findings:Finding[]=[];
 const u=urgent.filter(x=>t.includes(x)); const c=credential.filter(x=>t.includes(x)); const m=money.filter(x=>t.includes(x));
 if(u.length) findings.push({label:'Urgency / pressure language',detail:`Detected: ${u.join(', ')}`,severity:'high'});
 if(c.length) findings.push({label:'Credential or OTP request',detail:`Detected: ${c.join(', ')}`,severity:'high'});
 if(m.length) findings.push({label:'Payment red flags',detail:`Detected: ${m.join(', ')}`,severity:'medium'});
 const links=text.match(/https?:\/\/[^\s<>"')]+/gi)||[];
 if(links.length) findings.push({label:'Links detected',detail:`${links.length} link(s) found. Check each domain separately before opening.`,severity:'medium'});
 if(!findings.length) findings.push({label:'No obvious heuristic indicators',detail:'This is not proof that the message is safe. Verify the sender independently.',severity:'low'});
 const score=Math.min(98,(u.length*22)+(c.length*28)+(m.length*14)+(links.length*12));
 return {id:crypto.randomUUID(),kind:'MESSAGE',target:text.slice(0,100),score,level:score>=60?'HIGH':score>=25?'MEDIUM':'LOW',date:new Date().toISOString(),findings};
}
export function analyzeUrl(raw:string): Scan {
 let score=0; const findings:Finding[]=[]; let host='';
 try {
  const u=new URL(raw); host=u.hostname.toLowerCase();
  if(!['http:','https:'].includes(u.protocol)) throw new Error('Only HTTP and HTTPS URLs are supported.');
  if(u.username||u.password){score+=35;findings.push({label:'Embedded credentials',detail:'The URL contains a username or password component.',severity:'high'});}
  if(u.protocol==='http:'){score+=15;findings.push({label:'Unencrypted connection',detail:'HTTP does not protect data in transit like HTTPS.',severity:'medium'});}
  if(/^(localhost|127\.|10\.|192\.168\.|172\.(1[6-9]|2\d|3[01])\.)/.test(host)){score+=45;findings.push({label:'Private or loopback host',detail:'This destination appears to be local/private. Do not submit internal addresses to public scanners.',severity:'high'});}
  if(host.split('.').length>4){score+=12;findings.push({label:'Unusually nested hostname',detail:'The hostname has many subdomains. Check for lookalike domains.',severity:'medium'});}
  if(host.includes('xn--')){score+=20;findings.push({label:'Internationalized hostname',detail:'Punycode can be legitimate but may also disguise lookalike characters.',severity:'medium'});}
  if(/login|verify|secure|wallet|bonus|gift|claim|update-account/.test(host)){score+=15;findings.push({label:'Sensitive wording in hostname',detail:'The hostname contains terms commonly used in impersonation campaigns.',severity:'medium'});}
  if(!findings.length) findings.push({label:'No obvious URL structure red flags',detail:'A clean-looking URL is not a safety guarantee. Check reputation with trusted threat-intelligence providers.',severity:'low'});
 } catch(e){findings.push({label:'Invalid URL',detail:e instanceof Error?e.message:'Enter a complete URL.',severity:'high'});score=70;}
 score=Math.min(98,score);
 return {id:crypto.randomUUID(),kind:'URL',target:raw,score,level:score>=60?'HIGH':score>=25?'MEDIUM':'LOW',date:new Date().toISOString(),findings};
}
export function analyzeProduct(text:string): Scan {
 const t=text.toLowerCase(); const findings:Finding[]=[]; let score=0;
 const rules=[['Unrealistic discount',/(\b[89]\d%\s*off\b|\b\d{2,3}%\s*discount\b)/,'high',35],['Off-platform payment pressure',/(pay outside|direct transfer|personal upi|friends and family)/,'high',35],['Advance-fee language',/(advance fee|customs fee|release fee|processing charge)/,'medium',20],['No-return / no-refund claim',/(no refund|no return|non-refundable)/,'medium',15]];
 for(const [label,regex,severity,points] of rules as any){if(regex.test(t)){score+=points;findings.push({label,detail:'Potential e-commerce scam indicator. Verify the seller and payment protections.',severity});}}
 if(!findings.length)findings.push({label:'No obvious listing red flags',detail:'Check seller history, independent reviews, return policy and protected payment options.',severity:'low'});
 score=Math.min(98,score); return {id:crypto.randomUUID(),kind:'PRODUCT',target:text.slice(0,100),score,level:score>=60?'HIGH':score>=25?'MEDIUM':'LOW',date:new Date().toISOString(),findings};
}