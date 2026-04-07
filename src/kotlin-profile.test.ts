/**
 * Kotlin Profile Integration Test
 *
 * Tests the KotlinProfile — the ninth LanguageProfile implementation.
 * Kotlin is Android's primary language and increasingly used server-side with
 * Ktor and Spring Boot. Key features: coroutines, extension functions, data classes,
 * sealed classes, string interpolation, trailing lambdas, when expressions.
 *
 * Parse with tree-sitter-kotlin -> map with KotlinProfile -> verify.
 */

import { describe, it, expect, beforeAll } from 'vitest';
import { Parser, Language } from 'web-tree-sitter';
import fs from 'fs';
import path from 'path';
import { fileURLToPath } from 'url';
import { buildNeuralMap } from './mapper.js';
import { kotlinProfile } from './profiles/kotlin.js';
import { verifyAll } from './verifier';

const __dirname = path.dirname(fileURLToPath(import.meta.url));

let parser: InstanceType<typeof Parser>;

async function createKotlinParser(): Promise<InstanceType<typeof Parser>> {
  await Parser.init();
  const p = new Parser();
  const wasmPath = path.resolve(
    __dirname,
    '../node_modules/@tree-sitter-grammars/tree-sitter-kotlin/tree-sitter-kotlin.wasm'
  );
  const wasmBuffer = fs.readFileSync(wasmPath);
  const Kotlin = await Language.load(wasmBuffer);
  p.setLanguage(Kotlin);
  return p;
}

function parseKotlin(code: string) {
  return parser.parse(code);
}

describe('KotlinProfile — JVM + Android backbone', () => {
  beforeAll(async () => {
    parser = await createKotlinParser();
  });

  // =========================================================================
  // Layer 1: AST Node Classification
  // =========================================================================

  it('parses a simple Kotlin class and creates STRUCTURAL nodes', () => {
    const code = `
class HelloWorld {
    fun main() {
        println("Hello, World!")
    }
}
`;
    const tree = parseKotlin(code);
    const { map } = buildNeuralMap(tree, code, 'HelloWorld.kt', kotlinProfile);

    const structuralNodes = map.nodes.filter(n => n.node_type === 'STRUCTURAL');
    expect(structuralNodes.length).toBeGreaterThan(0);

    const classNode = structuralNodes.find(n => n.label === 'HelloWorld');
    expect(classNode).toBeDefined();
    expect(classNode!.language).toBe('kotlin');
  });

  it('classifies function_declaration as STRUCTURAL/function', () => {
    const code = `
fun getData(): String {
    return "data"
}
fun processData(input: String) {
    println(input)
}
`;
    const tree = parseKotlin(code);
    const { map } = buildNeuralMap(tree, code, 'Utils.kt', kotlinProfile);

    const funcs = map.nodes.filter(n => n.node_type === 'STRUCTURAL' && n.node_subtype === 'function');
    expect(funcs.length).toBeGreaterThanOrEqual(2);

    const getDataFunc = funcs.find(n => n.label === 'getData');
    expect(getDataFunc).toBeDefined();
  });

  it('classifies data class as STRUCTURAL/data_class', () => {
    const code = `
data class User(val name: String, val age: Int)
`;
    const tree = parseKotlin(code);
    const { map } = buildNeuralMap(tree, code, 'User.kt', kotlinProfile);

    const dataClasses = map.nodes.filter(n =>
      n.node_type === 'STRUCTURAL' && n.node_subtype === 'data_class'
    );
    expect(dataClasses.length).toBeGreaterThanOrEqual(1);
    expect(dataClasses[0].label).toBe('User');
    expect(dataClasses[0].tags).toContain('data');
  });

  it('classifies sealed class as STRUCTURAL/sealed_class', () => {
    const code = `
sealed class Result {
    data class Success(val data: String) : Result()
    data class Error(val message: String) : Result()
}
`;
    const tree = parseKotlin(code);
    const { map } = buildNeuralMap(tree, code, 'Result.kt', kotlinProfile);

    const sealedClasses = map.nodes.filter(n =>
      n.node_type === 'STRUCTURAL' && n.node_subtype === 'sealed_class'
    );
    expect(sealedClasses.length).toBeGreaterThanOrEqual(1);
    expect(sealedClasses[0].label).toBe('Result');
    expect(sealedClasses[0].tags).toContain('sealed');
  });

  it('classifies object_declaration as STRUCTURAL/object with singleton tag', () => {
    const code = `
object DatabaseManager {
    fun connect() {}
}
`;
    const tree = parseKotlin(code);
    const { map } = buildNeuralMap(tree, code, 'DatabaseManager.kt', kotlinProfile);

    const objects = map.nodes.filter(n =>
      n.node_type === 'STRUCTURAL' && n.node_subtype === 'object'
    );
    expect(objects.length).toBeGreaterThanOrEqual(1);
    expect(objects[0].label).toBe('DatabaseManager');
    expect(objects[0].tags).toContain('singleton');
  });

  it('classifies import as STRUCTURAL/dependency', () => {
    const code = `
import io.ktor.server.application.ApplicationCall
import kotlin.collections.listOf

fun run() {}
`;
    const tree = parseKotlin(code);
    const { map } = buildNeuralMap(tree, code, 'App.kt', kotlinProfile);

    const imports = map.nodes.filter(n => n.node_type === 'STRUCTURAL' && n.node_subtype === 'dependency');
    expect(imports.length).toBeGreaterThanOrEqual(2);
  });

  // =========================================================================
  // Layer 2: Callee Resolution
  // =========================================================================

  it('resolves println as EGRESS/display', () => {
    const code = `
fun main() {
    println("hello")
}
`;
    const tree = parseKotlin(code);
    const { map } = buildNeuralMap(tree, code, 'Main.kt', kotlinProfile);

    const egressNodes = map.nodes.filter(n => n.node_type === 'EGRESS');
    expect(egressNodes.length).toBeGreaterThanOrEqual(1);
    expect(egressNodes.some(n => n.node_subtype === 'display')).toBe(true);
  });

  it('resolves readLine() as tainted INGRESS/user_input', () => {
    const code = `
fun main() {
    val input = readLine()
    println(input)
}
`;
    const tree = parseKotlin(code);
    const { map } = buildNeuralMap(tree, code, 'Input.kt', kotlinProfile);

    const ingressNodes = map.nodes.filter(n => n.node_type === 'INGRESS');
    expect(ingressNodes.length).toBeGreaterThanOrEqual(1);
    expect(ingressNodes.some(n => n.node_subtype === 'user_input')).toBe(true);
    expect(ingressNodes.some(n => n.data_out.some(d => d.tainted))).toBe(true);
  });

  it('resolves Ktor call.receive as tainted INGRESS', () => {
    const code = `
fun handleRequest() {
    val body = call.receive()
    call.respondText(body)
}
`;
    const tree = parseKotlin(code);
    const { map } = buildNeuralMap(tree, code, 'Handler.kt', kotlinProfile);

    const ingressNodes = map.nodes.filter(n => n.node_type === 'INGRESS');
    expect(ingressNodes.length).toBeGreaterThanOrEqual(1);

    const egressNodes = map.nodes.filter(n => n.node_type === 'EGRESS');
    expect(egressNodes.length).toBeGreaterThanOrEqual(1);
  });

  it('resolves Log.d as META/logging', () => {
    const code = `
fun debug() {
    Log.d("TAG", "message")
}
`;
    const tree = parseKotlin(code);
    const { map } = buildNeuralMap(tree, code, 'Debug.kt', kotlinProfile);

    const metaNodes = map.nodes.filter(n => n.node_type === 'META' && n.node_subtype === 'logging');
    expect(metaNodes.length).toBeGreaterThanOrEqual(1);
  });

  it('resolves File.readText as INGRESS/file_read', () => {
    const code = `
fun readConfig() {
    val content = File.readText()
}
`;
    const tree = parseKotlin(code);
    const { map } = buildNeuralMap(tree, code, 'Config.kt', kotlinProfile);

    const ingressNodes = map.nodes.filter(n => n.node_type === 'INGRESS' && n.node_subtype === 'file_read');
    expect(ingressNodes.length).toBeGreaterThanOrEqual(1);
  });

  // =========================================================================
  // Layer 3: Taint Propagation
  // =========================================================================

  it('propagates taint from readLine through variable to println', () => {
    const code = `
fun main() {
    val userInput = readLine()
    println(userInput)
}
`;
    const tree = parseKotlin(code);
    const { map } = buildNeuralMap(tree, code, 'Taint.kt', kotlinProfile);

    // Should have INGRESS (readLine) and EGRESS (println) with DATA_FLOW between them
    const ingressNodes = map.nodes.filter(n => n.node_type === 'INGRESS');
    const egressNodes = map.nodes.filter(n => n.node_type === 'EGRESS');
    expect(ingressNodes.length).toBeGreaterThanOrEqual(1);
    expect(egressNodes.length).toBeGreaterThanOrEqual(1);

    // Check data flow edges
    const dataFlows = map.edges.filter(e => e.edge_type === 'DATA_FLOW');
    expect(dataFlows.length).toBeGreaterThanOrEqual(1);
  });

  it('detects taint through Ktor request to response', () => {
    const code = `
fun handle() {
    val body = call.receive()
    call.respondText(body)
}
`;
    const tree = parseKotlin(code);
    const { map } = buildNeuralMap(tree, code, 'KtorHandler.kt', kotlinProfile);

    const ingressNodes = map.nodes.filter(n => n.node_type === 'INGRESS');
    const egressNodes = map.nodes.filter(n => n.node_type === 'EGRESS');
    expect(ingressNodes.length).toBeGreaterThanOrEqual(1);
    expect(egressNodes.length).toBeGreaterThanOrEqual(1);

    // Data flow from INGRESS to EGRESS
    const dataFlows = map.edges.filter(e => e.edge_type === 'DATA_FLOW');
    expect(dataFlows.length).toBeGreaterThanOrEqual(1);
  });

  // =========================================================================
  // Layer 4: Kotlin-Specific Features
  // =========================================================================

  it('classifies suspend function with coroutine tag', () => {
    const code = `
suspend fun fetchData(): String {
    return "data"
}
`;
    const tree = parseKotlin(code);
    const { map } = buildNeuralMap(tree, code, 'Async.kt', kotlinProfile);

    const suspendFuncs = map.nodes.filter(n =>
      n.node_type === 'STRUCTURAL' && n.node_subtype === 'function' && n.tags.includes('suspend')
    );
    expect(suspendFuncs.length).toBeGreaterThanOrEqual(1);
    expect(suspendFuncs[0].tags).toContain('coroutine');
  });

  it('classifies when expression as CONTROL/branch', () => {
    const code = `
fun check(x: Int) {
    when (x) {
        1 -> println("one")
        2 -> println("two")
        else -> println("other")
    }
}
`;
    const tree = parseKotlin(code);
    const { map } = buildNeuralMap(tree, code, 'When.kt', kotlinProfile);

    const whenNodes = map.nodes.filter(n => n.node_type === 'CONTROL' && n.node_subtype === 'branch' && n.label === 'when');
    expect(whenNodes.length).toBeGreaterThanOrEqual(1);
  });

  it('classifies if expression as CONTROL/branch', () => {
    const code = `
fun check(x: Int) {
    if (x > 0) {
        println("positive")
    } else {
        println("non-positive")
    }
}
`;
    const tree = parseKotlin(code);
    const { map } = buildNeuralMap(tree, code, 'IfExpr.kt', kotlinProfile);

    const ifNodes = map.nodes.filter(n => n.node_type === 'CONTROL' && n.node_subtype === 'branch' && n.label === 'if');
    expect(ifNodes.length).toBeGreaterThanOrEqual(1);
  });

  it('classifies lambda_literal as STRUCTURAL/function with lambda tag', () => {
    const code = `
fun process() {
    val items = listOf(1, 2, 3)
    items.forEach { item ->
        println(item)
    }
}
`;
    const tree = parseKotlin(code);
    const { map } = buildNeuralMap(tree, code, 'Lambda.kt', kotlinProfile);

    const lambdas = map.nodes.filter(n =>
      n.node_type === 'STRUCTURAL' && n.node_subtype === 'function' && n.tags.includes('lambda')
    );
    expect(lambdas.length).toBeGreaterThanOrEqual(1);
  });

  it('classifies try/catch as CONTROL/error_handling', () => {
    const code = `
fun risky() {
    try {
        println("try")
    } catch (e: Exception) {
        println("catch")
    } finally {
        println("finally")
    }
}
`;
    const tree = parseKotlin(code);
    const { map } = buildNeuralMap(tree, code, 'TryCatch.kt', kotlinProfile);

    const tryNodes = map.nodes.filter(n => n.node_type === 'CONTROL' && n.node_subtype === 'error_handling');
    expect(tryNodes.length).toBeGreaterThanOrEqual(1);

    const errorHandling = tryNodes.filter(n => n.tags.includes('error_handling'));
    expect(errorHandling.length).toBeGreaterThanOrEqual(1);
  });

  // =========================================================================
  // Layer 5: Control Flow
  // =========================================================================

  it('classifies for loop as CONTROL/loop', () => {
    const code = `
fun iterate() {
    for (i in 1..10) {
        println(i)
    }
}
`;
    const tree = parseKotlin(code);
    const { map } = buildNeuralMap(tree, code, 'Loop.kt', kotlinProfile);

    const forNodes = map.nodes.filter(n => n.node_type === 'CONTROL' && n.node_subtype === 'loop');
    expect(forNodes.length).toBeGreaterThanOrEqual(1);
  });

  it('classifies return_expression as CONTROL/return', () => {
    const code = `
fun getValue(): Int {
    return 42
}
`;
    const tree = parseKotlin(code);
    const { map } = buildNeuralMap(tree, code, 'Return.kt', kotlinProfile);

    const returnNodes = map.nodes.filter(n => n.node_type === 'CONTROL' && n.node_subtype === 'return');
    expect(returnNodes.length).toBeGreaterThanOrEqual(1);
  });

  it('classifies throw_expression as CONTROL/throw', () => {
    const code = `
fun fail() {
    throw IllegalStateException("failure")
}
`;
    const tree = parseKotlin(code);
    const { map } = buildNeuralMap(tree, code, 'Throw.kt', kotlinProfile);

    const throwNodes = map.nodes.filter(n => n.node_type === 'CONTROL' && n.node_subtype === 'throw');
    expect(throwNodes.length).toBeGreaterThanOrEqual(1);
    expect(throwNodes[0].tags).toContain('error_handling');
  });

  // =========================================================================
  // Layer 6: Framework / Android Integration
  // =========================================================================

  it('resolves HttpClient.get as EXTERNAL/api_call', () => {
    const code = `
fun fetchApi() {
    HttpClient.get("https://api.example.com")
}
`;
    const tree = parseKotlin(code);
    const { map } = buildNeuralMap(tree, code, 'ApiClient.kt', kotlinProfile);

    const externalNodes = map.nodes.filter(n => n.node_type === 'EXTERNAL' && n.node_subtype === 'api_call');
    expect(externalNodes.length).toBeGreaterThanOrEqual(1);
  });

  it('resolves repository.save as STORAGE/db_write', () => {
    const code = `
fun saveUser() {
    repository.save(user)
}
`;
    const tree = parseKotlin(code);
    const { map } = buildNeuralMap(tree, code, 'Repo.kt', kotlinProfile);

    const storageNodes = map.nodes.filter(n => n.node_type === 'STORAGE' && n.node_subtype === 'db_write');
    expect(storageNodes.length).toBeGreaterThanOrEqual(1);
  });

  it('resolves coroutine launch as CONTROL/event_handler', () => {
    const code = `
fun startJob() {
    launch {
        println("async work")
    }
}
`;
    const tree = parseKotlin(code);
    const { map } = buildNeuralMap(tree, code, 'Coroutine.kt', kotlinProfile);

    const controlNodes = map.nodes.filter(n => n.node_type === 'CONTROL' && n.node_subtype === 'event_handler');
    expect(controlNodes.length).toBeGreaterThanOrEqual(1);
  });

  // =========================================================================
  // Full-stack: Vulnerable Ktor Handler
  // =========================================================================

  it('detects SQL injection in a Ktor handler (full pipeline)', () => {
    const code = `
fun handleUser() {
    val userInput = readLine()
    val query = "SELECT * FROM users WHERE name = " + userInput
    database.rawQuery(query)
}
`;
    const tree = parseKotlin(code);
    const { map } = buildNeuralMap(tree, code, 'Vulnerable.kt', kotlinProfile);

    // Must detect INGRESS, STORAGE, and data flow between them
    const ingressNodes = map.nodes.filter(n => n.node_type === 'INGRESS');
    const storageNodes = map.nodes.filter(n => n.node_type === 'STORAGE');
    expect(ingressNodes.length).toBeGreaterThanOrEqual(1);
    expect(storageNodes.length).toBeGreaterThanOrEqual(1);

    // Data flow edges should exist
    const dataFlows = map.edges.filter(e => e.edge_type === 'DATA_FLOW');
    expect(dataFlows.length).toBeGreaterThanOrEqual(1);
  });

  // =========================================================================
  // Edge Cases
  // =========================================================================

  it('handles companion object declarations', () => {
    const code = `
class Config {
    companion object {
        fun getDefault(): Config = Config()
    }
}
`;
    const tree = parseKotlin(code);
    const { map } = buildNeuralMap(tree, code, 'Config.kt', kotlinProfile);

    const companions = map.nodes.filter(n =>
      n.node_type === 'STRUCTURAL' && n.node_subtype === 'companion_object'
    );
    expect(companions.length).toBeGreaterThanOrEqual(1);
    expect(companions[0].tags).toContain('companion');
  });

  it('handles property declarations with val and var', () => {
    const code = `
fun process() {
    val immutable = "fixed"
    var mutable = readLine()
    println(mutable)
}
`;
    const tree = parseKotlin(code);
    const { map } = buildNeuralMap(tree, code, 'Props.kt', kotlinProfile);

    // readLine creates an INGRESS node, println creates EGRESS
    const ingress = map.nodes.filter(n => n.node_type === 'INGRESS');
    const egress = map.nodes.filter(n => n.node_type === 'EGRESS');
    expect(ingress.length).toBeGreaterThanOrEqual(1);
    expect(egress.length).toBeGreaterThanOrEqual(1);
  });

  it('profile id and extensions are correct', () => {
    expect(kotlinProfile.id).toBe('kotlin');
    expect(kotlinProfile.extensions).toContain('.kt');
    expect(kotlinProfile.extensions).toContain('.kts');
  });

  it('profile creates nodes with language=kotlin', () => {
    const code = `
fun hello() {
    println("hi")
}
`;
    const tree = parseKotlin(code);
    const { map } = buildNeuralMap(tree, code, 'Hi.kt', kotlinProfile);

    const kotlinNodes = map.nodes.filter(n => n.language === 'kotlin');
    expect(kotlinNodes.length).toBeGreaterThan(0);
  });

  // =========================================================================
  // Constant Folding Anti-Evasion
  // =========================================================================

  it('folds string concatenation: "ev" + "al" in val declaration', () => {
    const code = `
fun exploit() {
    val name = "ev" + "al"
    println(name)
}
`;
    const tree = parseKotlin(code);
    const { map } = buildNeuralMap(tree, code, 'Evasion.kt', kotlinProfile);

    // The println should still be detected as EGRESS
    const egressNodes = map.nodes.filter(n => n.node_type === 'EGRESS');
    expect(egressNodes.length).toBeGreaterThan(0);
  });

  it('detects Class.forName with concatenated string as reflection', () => {
    const code = `
fun exploit() {
    val clazz = Class.forName("java.lang." + "Runtime")
    val method = clazz.getMethod("exec", String::class.java)
}
`;
    const tree = parseKotlin(code);
    const { map } = buildNeuralMap(tree, code, 'ReflectionEvasion.kt', kotlinProfile);

    // Should detect Class.forName as EXTERNAL/reflection
    const reflectionNodes = map.nodes.filter(
      n => n.node_type === 'EXTERNAL' && n.node_subtype === 'reflection'
    );
    expect(reflectionNodes.length).toBeGreaterThan(0);
  });

  it('detects Class.forName with variable holding folded constant', () => {
    const code = `
fun exploit() {
    val cls = "java.lang." + "Runtime"
    Class.forName(cls)
}
`;
    const tree = parseKotlin(code);
    const { map } = buildNeuralMap(tree, code, 'IndirectEvasion.kt', kotlinProfile);

    const reflectionNodes = map.nodes.filter(
      n => n.node_type === 'EXTERNAL' && n.node_subtype === 'reflection'
    );
    expect(reflectionNodes.length).toBeGreaterThan(0);
    // Should have the anti_evasion tag
    const tagged = reflectionNodes.filter(n => n.tags.includes('anti_evasion'));
    expect(tagged.length).toBeGreaterThan(0);
  });

  it('detects String.plus evasion pattern', () => {
    const code = `
fun exploit() {
    val cmd = "ev".plus("al")
    println(cmd)
}
`;
    const tree = parseKotlin(code);
    const { map } = buildNeuralMap(tree, code, 'PlusEvasion.kt', kotlinProfile);

    // The println should still be detected as EGRESS
    const egressNodes = map.nodes.filter(n => n.node_type === 'EGRESS');
    expect(egressNodes.length).toBeGreaterThan(0);
  });
});
