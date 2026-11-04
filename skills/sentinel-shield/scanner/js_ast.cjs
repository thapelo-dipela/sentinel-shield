#!/usr/bin/env node
'use strict';
/* Trusted-only TypeScript AST reader. Never imports target modules or loads target configs.
 * Requires a hash-verified compiler file outside the audited repository and Node's read-only
 * permission sandbox. No implicit require('typescript') or developer-specific fallback.
 */
const fs = require('node:fs');
const path = require('node:path');
const crypto = require('node:crypto');
const args = process.argv;
function option(key) {const i=args.indexOf(key);return i<0?'':args[i+1]||'';}
const rootArg = option('--root'), compilerArg = option('--compiler'), compilerHash = option('--compiler-sha256');
if(!rootArg || !compilerArg || !/^[0-9a-f]{64}$/i.test(compilerHash)) {
  process.stderr.write('missing verified compiler parameters\n');process.exit(2);
}
let root, ts;
try {
  root=fs.realpathSync(rootArg);
  const compiler=fs.realpathSync(compilerArg);
  if(compiler!==path.resolve(compilerArg) || compiler===root || compiler.startsWith(root+path.sep))throw Error('untrusted compiler location');
  if(!fs.statSync(compiler).isFile()||fs.statSync(compiler).size>16000000)throw Error('compiler size');
  const actual=crypto.createHash('sha256').update(fs.readFileSync(compiler)).digest('hex');
  if(actual!==compilerHash.toLowerCase())throw Error('compiler hash mismatch');
  ts=require(compiler); // Absolute, previously verified path only. Never search node_modules.
  if(typeof ts.createSourceFile!=='function' || !ts.SyntaxKind)throw Error('not TypeScript compiler');
} catch(e){process.stderr.write('untrusted TypeScript compiler: '+e.name+'\n');process.exit(2);}
const ignored=new Set(['.git','node_modules','.venv','venv','vendor','dist','build','.next','coverage','__pycache__']);
const exts=new Set(['.js','.jsx','.ts','.tsx','.mjs','.cjs']);
const findings=[],gaps=[];
let used=0,count=0,work=0,helpers=0;
const MAX_WORK=90000,MAX_HELPERS=350,MAX_DEPTH=8,MAX_AST_DEPTH=200,MAX_ITEMS=2200;
class BudgetError extends Error { constructor(message){super(message);this.name='BudgetError';} }
function tick(){if(++work>MAX_WORK)throw new BudgetError('node AST work budget');}
function hash(s){return crypto.createHash('sha256').update(String(s)).digest('hex').slice(0,12);}
function unique(items){const m=new Map();for(const f of items){m.set(f.source+'|'+f.steps.join('|'),f);if(m.size>=12)break;}return [...m.values()];}
function preflight(sf){
  let n=0;const todo=[[sf,0]];
  while(todo.length){const [node,depth]=todo.pop();if(++n>80000||depth>MAX_AST_DEPTH)throw new BudgetError('JS AST nesting/node budget');
    ts.forEachChild(node,ch=>{todo.push([ch,depth+1]);});
  }
}
function walk(dir){
  if(count>2500){gaps.push('JS file count limit reached');return;}
  for(const ent of fs.readdirSync(dir,{withFileTypes:true})){
    const file=path.join(dir,ent.name);
    if(ent.isSymbolicLink()){gaps.push('JS symlink skipped');continue;}
    if(ent.isDirectory()){
      if(ignored.has(ent.name)){gaps.push('JS excluded directory:'+ent.name);continue;}
      walk(file);continue;
    }
    if(!ent.isFile()||!exts.has(path.extname(ent.name).toLowerCase()))continue;
    if(++count>2500){gaps.push('JS file count limit reached');return;}
    const sz=fs.statSync(file).size;
    if(sz>800000||used+sz>25000000){gaps.push('JS source size budget skipped:'+hash(path.relative(root,file)));continue;}
    used+=sz;
    try{analyze(file);}catch(e){gaps.push('JS file analysis incomplete:'+hash(path.relative(root,file))+':'+e.name);}
  }
}
function analyze(file){
  const text=fs.readFileSync(file,'utf8'),rel=path.relative(root,file).replace(/\\/g,'/');
  const sf=ts.createSourceFile(rel,text,ts.ScriptTarget.Latest,true,/\.(tsx|jsx)$/.test(file)?ts.ScriptKind.TSX:ts.ScriptKind.TS);
  if(sf.parseDiagnostics?.length)gaps.push('JS parse error:'+hash(rel));
  preflight(sf);
  const funcs=new Map();
  function collect(node){tick();
    if(ts.isFunctionDeclaration(node)&&node.name)funcs.set(node.name.text,node);
    if(ts.isVariableDeclaration(node)&&ts.isIdentifier(node.name)&&node.initializer&&(ts.isArrowFunction(node.initializer)||ts.isFunctionExpression(node.initializer)))funcs.set(node.name.text,node.initializer);
    ts.forEachChild(node,collect);
  }collect(sf);
  function prop(n){
    if(!n)return '';
    if(ts.isIdentifier(n))return n.text;
    if(ts.isPropertyAccessExpression(n))return prop(n.expression)+'.'+n.name.text;
    if(ts.isElementAccessExpression(n))return prop(n.expression)+'[]';
    return '';
  }
  function source(n){
    if(!n)return '';
    const s=prop(n);
    if(/^(req|request)\.(body|query|params|cookies|headers)(?:\.|\[|$)/.test(s))return 'HTTP input '+s.slice(0,80);
    if(s==='window.location.search'||s==='location.search')return 'URL query input';
    if(ts.isCallExpression(n)&&/^(req|request)\.(json|text|formData)$/.test(prop(n.expression)))return 'HTTP request payload';
    return '';
  }
  const seen=new Set();
  function emit(rule,sev,sink,exp,flows){
    const line=sf.getLineAndCharacterOfPosition(exp.getStart(sf)).line+1;
    for(const flow of flows.slice(0,6)){
      const id=[rule,line,flow.source,sink].join('|');
      if(!seen.has(id)){seen.add(id);if(findings.length<MAX_ITEMS)findings.push({rule,severity:sev,confidence:'MEDIUM',file:rel,line,source:flow.source,sink,trace:[...flow.steps,`sink:${sink}`]});else gaps.push('JS finding count limit reached');}
    }
  }
  function evaluate(n,state,stack,depth){tick();
    if(!n)return [];
    const src=source(n);if(src)return [{source:src,steps:[`source:${src}`]}];
    if(ts.isIdentifier(n))return state.get(n.text)||[];
    if(ts.isParenthesizedExpression(n)||ts.isAsExpression(n)||ts.isTypeAssertionExpression(n)||ts.isNonNullExpression(n)||ts.isAwaitExpression(n))return evaluate(n.expression,state,stack,depth);
    if(ts.isPropertyAccessExpression(n)||ts.isElementAccessExpression(n))return evaluate(n.expression,state,stack,depth);
    if(ts.isBinaryExpression(n))return unique([...evaluate(n.left,state,stack,depth),...evaluate(n.right,state,stack,depth)]);
    if(ts.isConditionalExpression(n))return unique([...evaluate(n.whenTrue,state,stack,depth),...evaluate(n.whenFalse,state,stack,depth)]);
    if(ts.isTemplateExpression(n))return unique(n.templateSpans.flatMap(s=>evaluate(s.expression,state,stack,depth)));
    if(ts.isArrayLiteralExpression(n))return unique(n.elements.flatMap(x=>evaluate(x,state,stack,depth)));
    if(ts.isObjectLiteralExpression(n))return unique(n.properties.flatMap(x=>ts.isPropertyAssignment(x)?evaluate(x.initializer,state,stack,depth):[]));
    if(ts.isCallExpression(n)){
      const name=prop(n.expression);
      if(['Number','parseInt','parseFloat','Boolean'].includes(name))return [];
      const values=unique([...n.arguments.flatMap(a=>evaluate(a,state,stack,depth)),
        ...(ts.isPropertyAccessExpression(n.expression)?evaluate(n.expression.expression,state,stack,depth):[])]);
      if(funcs.has(name)){
        if(depth>=MAX_DEPTH||stack.includes(name)){gaps.push('JS helper depth or recursion unsupported');return values;}
        if(++helpers>MAX_HELPERS)throw new BudgetError('JS helper budget exceeded');
        const fn=funcs.get(name),inner=new Map();
        fn.parameters?.forEach((p,i)=>{if(ts.isIdentifier(p.name))inner.set(p.name.text,evaluate(n.arguments[i],state,stack,depth).map(f=>({...f,steps:[...f.steps,`call:${name}`]})));});
        const returned=processStatements(fn.body,inner,[...stack,name],depth+1);
        return unique(returned.map(f=>({...f,steps:[...f.steps,`call:${name}`]})));
      }
      return values;
    }
    return [];
  }
  function inspect(n,state,stack,depth){if(!n)return;tick();
    if(ts.isCallExpression(n)){
      const name=prop(n.expression), arg=n.arguments[0];
      if(arg){const values=evaluate(arg,state,stack,depth);
        if(values.length){
          if(name==='eval'||name==='Function')emit('JS-CODE-EVAL','CRITICAL','dynamic evaluation',n,values);
          else if(/^(child_process\.)?(exec|execSync)$/.test(name))emit('JS-CMD-TAINT','HIGH','shell invocation',n,values);
          else if(/(?:^|\.)(query|raw|execute)$/.test(name))emit('JS-SQL-TAINT','HIGH','dynamic database query',n,values);
          else if(['fetch','axios.get','axios.post','http.get','https.get'].includes(name))emit('JS-SSRF-TAINT','MEDIUM','outbound request destination',n,values);
        }
      }
      if(funcs.has(name))evaluate(n,state,stack,depth);
    }
    if(ts.isBinaryExpression(n)&&n.operatorToken.kind===ts.SyntaxKind.EqualsToken){
      const target=prop(n.left),flows=evaluate(n.right,state,stack,depth);
      if(/\.innerHTML$/.test(target)&&flows.length)emit('JS-XSS-TAINT','HIGH','HTML insertion',n,flows);
    }
    ts.forEachChild(n,ch=>{if(ts.isFunctionLike(ch))return;
      if(ts.isCallExpression(ch)||ts.isBinaryExpression(ch)||ts.isAwaitExpression(ch))inspect(ch,state,stack,depth);
    });
  }
  function blend(state,scopes){for(const s of scopes)for(const [k,v] of s)state.set(k,unique([...(state.get(k)||[]),...v]));}
  function processStatements(body,state,stack,depth){if(!body)return [];tick();
    if(depth>MAX_DEPTH){gaps.push('JS helper depth limit');return [];}
    let list=ts.isBlock(body)||ts.isSourceFile(body)?body.statements:[body],returns=[];
    for(const stmt of list){tick();
      if(ts.isVariableStatement(stmt)){
        for(const dec of stmt.declarationList.declarations)if(dec.initializer){inspect(dec.initializer,state,stack,depth);if(ts.isIdentifier(dec.name))state.set(dec.name.text,evaluate(dec.initializer,state,stack,depth));}
      }else if(ts.isExpressionStatement(stmt)){
        const exp=stmt.expression;inspect(exp,state,stack,depth);
        if(ts.isBinaryExpression(exp)&&exp.operatorToken.kind===ts.SyntaxKind.EqualsToken&&ts.isIdentifier(exp.left))state.set(exp.left.text,evaluate(exp.right,state,stack,depth));
      }else if(ts.isReturnStatement(stmt)){
        inspect(stmt.expression,state,stack,depth);returns.push(...evaluate(stmt.expression,state,stack,depth));
      }else if(ts.isIfStatement(stmt)){
        inspect(stmt.expression,state,stack,depth);
        const a=new Map(state),b=new Map(state);
        returns.push(...processStatements(stmt.thenStatement,a,stack,depth));
        if(stmt.elseStatement)returns.push(...processStatements(stmt.elseStatement,b,stack,depth));
        blend(state,[a,b]);
      }else if(ts.isTryStatement(stmt)){
        const branches=[];
        for(const branch of [stmt.tryBlock,stmt.catchClause?.block,stmt.finallyBlock])if(branch){const tmp=new Map(state);returns.push(...processStatements(branch,tmp,stack,depth));branches.push(tmp);}
        blend(state,branches);
      }else if(ts.isForOfStatement(stmt)||ts.isForInStatement(stmt)){
        const inside=new Map(state),flows=evaluate(stmt.expression,inside,stack,depth);
        if(ts.isVariableDeclarationList(stmt.initializer)){
          for(const dec of stmt.initializer.declarations)if(ts.isIdentifier(dec.name))inside.set(dec.name.text,flows);
        }else if(ts.isIdentifier(stmt.initializer))inside.set(stmt.initializer.text,flows);
        returns.push(...processStatements(stmt.statement,inside,stack,depth));blend(state,[inside]);
      }else if(ts.isForStatement(stmt)||ts.isWhileStatement(stmt)||ts.isDoStatement(stmt)){
        const inside=new Map(state);
        if(ts.isForStatement(stmt)){
          if(stmt.initializer && ts.isVariableDeclarationList(stmt.initializer))for(const dec of stmt.initializer.declarations)if(ts.isIdentifier(dec.name))inside.set(dec.name.text,evaluate(dec.initializer,inside,stack,depth));
          inspect(stmt.condition,inside,stack,depth);inspect(stmt.incrementor,inside,stack,depth);
        }else inspect(stmt.expression,inside,stack,depth);
        returns.push(...processStatements(stmt.statement,inside,stack,depth));blend(state,[inside]);
      }else if(ts.isSwitchStatement(stmt)){
        inspect(stmt.expression,state,stack,depth);
        const branches=[];
        for(const clause of stmt.caseBlock.clauses){const inside=new Map(state);returns.push(...processStatements({statements:clause.statements,kind:ts.SyntaxKind.SourceFile},inside,stack,depth));branches.push(inside);}
        blend(state,branches);
      }else if(ts.isBlock(stmt)){returns.push(...processStatements(stmt,state,stack,depth));}
      else if(ts.isExpression(stmt)){inspect(stmt,state,stack,depth);returns.push(...evaluate(stmt,state,stack,depth));}
      else if(ts.isFunctionDeclaration(stmt)||ts.isClassDeclaration(stmt)||ts.isInterfaceDeclaration(stmt)||ts.isTypeAliasDeclaration(stmt)||ts.isImportDeclaration(stmt)||ts.isExportDeclaration(stmt)||ts.isEmptyStatement(stmt)||ts.isBreakStatement(stmt)||ts.isContinueStatement(stmt)){
        if(ts.isClassDeclaration(stmt))for(const member of stmt.members)if(member.body)processStatements(member.body,new Map(state),stack,depth+1);
      }else{
        // Conservatively report constructs not fully modelled, rather than returning clean.
        gaps.push('JS unsupported statement: '+ts.SyntaxKind[stmt.kind]);
        ts.forEachChild(stmt,ch=>{if(ts.isCallExpression(ch))inspect(ch,state,stack,depth);});
      }
    }
    return unique(returns);
  }
  processStatements(sf,new Map(),[],0);
  for(const [name,fn] of funcs)processStatements(fn.body,new Map(),[name],0);
  function visitCallbacks(node){tick();
    if(ts.isArrowFunction(node)||ts.isFunctionExpression(node))processStatements(node.body,new Map(),[],0);
    ts.forEachChild(node,visitCallbacks);
  }visitCallbacks(sf);
}
try{walk(root);process.stdout.write(JSON.stringify({findings,gaps:[...new Set(gaps)],coverage:{files:count,typescript:ts.version}}));}
catch(e){process.stderr.write('JS parser incomplete: '+e.name+'\n');process.exit(3);}
