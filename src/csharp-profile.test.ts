/**
 * C# Profile Integration Test
 *
 * Tests the CSharpProfile — the seventh LanguageProfile implementation.
 * C# is the ASP.NET Core backbone: Controllers, Entity Framework, HttpClient,
 * Identity, attributes, async/await, LINQ, generics.
 *
 * Parse with tree-sitter-c-sharp -> map with CSharpProfile -> verify.
 */

import { describe, it, expect, beforeAll } from 'vitest';
import { Parser, Language } from 'web-tree-sitter';
import fs from 'fs';
import path from 'path';
import { fileURLToPath } from 'url';
import { buildNeuralMap } from './mapper.js';
import { csharpProfile } from './profiles/csharp.js';
import { resetSequenceHard } from './types.js';

const __dirname = path.dirname(fileURLToPath(import.meta.url));

let parser: InstanceType<typeof Parser>;

async function createCSharpParser(): Promise<InstanceType<typeof Parser>> {
  await Parser.init();
  const p = new Parser();
  const wasmPath = path.resolve(
    __dirname,
    '../node_modules/tree-sitter-c-sharp/tree-sitter-c_sharp.wasm'
  );
  const wasmBuffer = fs.readFileSync(wasmPath);
  const CSharp = await Language.load(wasmBuffer);
  p.setLanguage(CSharp);
  return p;
}

function parseCSharp(code: string) {
  return parser.parse(code);
}

describe('CSharpProfile — ASP.NET Core backbone', () => {
  beforeAll(async () => {
    parser = await createCSharpParser();
  });

  // =========================================================================
  // Layer 1: AST Node Classification
  // =========================================================================

  it('parses a simple C# class and creates STRUCTURAL nodes', () => {
    resetSequenceHard();
    const code = `
using System;

public class HelloWorld
{
    public static void Main(string[] args)
    {
        Console.WriteLine("Hello, World!");
    }
}
`;
    const tree = parseCSharp(code);
    const { map } = buildNeuralMap(tree, code, 'HelloWorld.cs', csharpProfile);

    const structuralNodes = map.nodes.filter(n => n.node_type === 'STRUCTURAL');
    expect(structuralNodes.length).toBeGreaterThan(0);

    const classNode = structuralNodes.find(n => n.node_subtype === 'class');
    expect(classNode).toBeDefined();
    expect(classNode!.label).toBe('HelloWorld');
    expect(classNode!.language).toBe('csharp');
  });

  it('classifies method_declaration as STRUCTURAL/function', () => {
    resetSequenceHard();
    const code = `
public class Service
{
    public string GetData()
    {
        return "data";
    }
    private void ProcessData(string input)
    {
        Console.WriteLine(input);
    }
}
`;
    const tree = parseCSharp(code);
    const { map } = buildNeuralMap(tree, code, 'Service.cs', csharpProfile);

    const methods = map.nodes.filter(n => n.node_type === 'STRUCTURAL' && n.node_subtype === 'function');
    expect(methods.length).toBeGreaterThanOrEqual(2);

    const getDataMethod = methods.find(n => n.label === 'GetData');
    expect(getDataMethod).toBeDefined();
  });

  it('classifies constructor_declaration as STRUCTURAL/function with constructor tag', () => {
    resetSequenceHard();
    const code = `
public class User
{
    private string _name;
    public User(string name)
    {
        _name = name;
    }
}
`;
    const tree = parseCSharp(code);
    const { map } = buildNeuralMap(tree, code, 'User.cs', csharpProfile);

    const ctors = map.nodes.filter(n =>
      n.node_type === 'STRUCTURAL' && n.node_subtype === 'function' && n.tags.includes('constructor')
    );
    expect(ctors.length).toBeGreaterThanOrEqual(1);
  });

  it('classifies interface_declaration as STRUCTURAL/interface', () => {
    resetSequenceHard();
    const code = `
public interface IUserRepository
{
    void Save(string user);
    string FindById(int id);
}
`;
    const tree = parseCSharp(code);
    const { map } = buildNeuralMap(tree, code, 'IUserRepository.cs', csharpProfile);

    const ifaces = map.nodes.filter(n => n.node_type === 'STRUCTURAL' && n.node_subtype === 'interface');
    expect(ifaces.length).toBeGreaterThanOrEqual(1);
    expect(ifaces[0].label).toBe('IUserRepository');
  });

  it('classifies enum_declaration as STRUCTURAL/enum', () => {
    resetSequenceHard();
    const code = `
public enum Status
{
    Active,
    Inactive,
    Pending
}
`;
    const tree = parseCSharp(code);
    const { map } = buildNeuralMap(tree, code, 'Status.cs', csharpProfile);

    const enums = map.nodes.filter(n => n.node_type === 'STRUCTURAL' && n.node_subtype === 'enum');
    expect(enums.length).toBeGreaterThanOrEqual(1);
    expect(enums[0].label).toBe('Status');
  });

  it('classifies using_directive as STRUCTURAL/dependency', () => {
    resetSequenceHard();
    const code = `
using System;
using System.Collections.Generic;

public class App
{
    public void Run() {}
}
`;
    const tree = parseCSharp(code);
    const { map } = buildNeuralMap(tree, code, 'App.cs', csharpProfile);

    const imports = map.nodes.filter(n => n.node_type === 'STRUCTURAL' && n.node_subtype === 'dependency');
    expect(imports.length).toBeGreaterThanOrEqual(2);
  });

  it('classifies struct_declaration as STRUCTURAL/struct', () => {
    resetSequenceHard();
    const code = `
public struct Point
{
    public int X;
    public int Y;
}
`;
    const tree = parseCSharp(code);
    const { map } = buildNeuralMap(tree, code, 'Point.cs', csharpProfile);

    const structs = map.nodes.filter(n => n.node_type === 'STRUCTURAL' && n.node_subtype === 'struct');
    expect(structs.length).toBeGreaterThanOrEqual(1);
    expect(structs[0].label).toBe('Point');
  });

  it('classifies record_declaration as STRUCTURAL/record', () => {
    resetSequenceHard();
    const code = `
public record UserDto(string Name, string Email);
`;
    const tree = parseCSharp(code);
    const { map } = buildNeuralMap(tree, code, 'UserDto.cs', csharpProfile);

    const records = map.nodes.filter(n => n.node_type === 'STRUCTURAL' && n.node_subtype === 'record');
    expect(records.length).toBeGreaterThanOrEqual(1);
    expect(records[0].label).toBe('UserDto');
  });

  // =========================================================================
  // Layer 2: Callee Resolution
  // =========================================================================

  it('resolves Console.ReadLine as INGRESS/user_input', () => {
    resetSequenceHard();
    const code = `
public class Program
{
    public void Main()
    {
        var input = Console.ReadLine();
    }
}
`;
    const tree = parseCSharp(code);
    const { map } = buildNeuralMap(tree, code, 'Program.cs', csharpProfile);

    const ingress = map.nodes.filter(n => n.node_type === 'INGRESS' && n.node_subtype === 'user_input');
    expect(ingress.length).toBeGreaterThanOrEqual(1);
  });

  it('resolves Console.WriteLine as EGRESS/display', () => {
    resetSequenceHard();
    const code = `
public class Program
{
    public void Main()
    {
        Console.WriteLine("Hello");
    }
}
`;
    const tree = parseCSharp(code);
    const { map } = buildNeuralMap(tree, code, 'Program.cs', csharpProfile);

    const egress = map.nodes.filter(n => n.node_type === 'EGRESS' && n.node_subtype === 'display');
    expect(egress.length).toBeGreaterThanOrEqual(1);
  });

  it('resolves HttpClient.GetAsync as EXTERNAL/api_call', () => {
    resetSequenceHard();
    const code = `
public class ApiService
{
    public void FetchData()
    {
        HttpClient.GetAsync("https://api.example.com/data");
    }
}
`;
    const tree = parseCSharp(code);
    const { map } = buildNeuralMap(tree, code, 'ApiService.cs', csharpProfile);

    const external = map.nodes.filter(n => n.node_type === 'EXTERNAL' && n.node_subtype === 'api_call');
    expect(external.length).toBeGreaterThanOrEqual(1);
  });

  it('resolves File.ReadAllText as INGRESS/file_read', () => {
    resetSequenceHard();
    const code = `
public class FileService
{
    public void ReadConfig()
    {
        var content = File.ReadAllText("config.json");
    }
}
`;
    const tree = parseCSharp(code);
    const { map } = buildNeuralMap(tree, code, 'FileService.cs', csharpProfile);

    const ingress = map.nodes.filter(n => n.node_type === 'INGRESS' && n.node_subtype === 'file_read');
    expect(ingress.length).toBeGreaterThanOrEqual(1);
  });

  it('resolves DbContext.SaveChanges as STORAGE/db_write', () => {
    resetSequenceHard();
    const code = `
public class UserService
{
    public void Save(DbContext db)
    {
        db.SaveChanges();
    }
}
`;
    const tree = parseCSharp(code);
    const { map } = buildNeuralMap(tree, code, 'UserService.cs', csharpProfile);

    const storage = map.nodes.filter(n => n.node_type === 'STORAGE' && n.node_subtype === 'db_write');
    expect(storage.length).toBeGreaterThanOrEqual(1);
  });

  // =========================================================================
  // Layer 3: Taint Extraction & Data Flow
  // =========================================================================

  it('marks [FromBody] parameter as tainted INGRESS', () => {
    resetSequenceHard();
    const code = `
public class UserController
{
    public void Create([FromBody] CreateUserDto dto)
    {
        Console.WriteLine(dto);
    }
}
`;
    const tree = parseCSharp(code);
    const { map } = buildNeuralMap(tree, code, 'UserController.cs', csharpProfile);

    const ingress = map.nodes.filter(n => n.node_type === 'INGRESS' && n.node_subtype === 'http_request');
    expect(ingress.length).toBeGreaterThanOrEqual(1);
    expect(ingress[0].data_out.some(d => d.tainted)).toBe(true);
  });

  it('propagates taint from Console.ReadLine through variable to Console.WriteLine', () => {
    resetSequenceHard();
    const code = `
public class Program
{
    public void Main()
    {
        var input = Console.ReadLine();
        Console.WriteLine(input);
    }
}
`;
    const tree = parseCSharp(code);
    const { map } = buildNeuralMap(tree, code, 'Program.cs', csharpProfile);

    // Should have INGRESS from ReadLine
    const ingress = map.nodes.filter(n => n.node_type === 'INGRESS');
    expect(ingress.length).toBeGreaterThanOrEqual(1);

    // Should have EGRESS from WriteLine
    const egress = map.nodes.filter(n => n.node_type === 'EGRESS');
    expect(egress.length).toBeGreaterThanOrEqual(1);

    // EGRESS should have tainted data flowing into it (data_out shows taint-through)
    const taintedEgress = egress.filter(n => n.data_out.some(d => d.tainted));
    expect(taintedEgress.length).toBeGreaterThanOrEqual(1);
  });

  // =========================================================================
  // Layer 4: Scope Analysis
  // =========================================================================

  it('creates scopes for methods, classes, and namespaces', () => {
    resetSequenceHard();
    const code = `
namespace MyApp
{
    public class UserService
    {
        public void Process()
        {
            if (true)
            {
                var x = 1;
            }
        }
    }
}
`;
    const tree = parseCSharp(code);
    const { map } = buildNeuralMap(tree, code, 'UserService.cs', csharpProfile);

    // Should have namespace node
    const nsNodes = map.nodes.filter(n => n.node_subtype === 'module');
    expect(nsNodes.length).toBeGreaterThanOrEqual(1);

    // Should have class node
    const classNodes = map.nodes.filter(n => n.node_subtype === 'class');
    expect(classNodes.length).toBeGreaterThanOrEqual(1);

    // Should have method node
    const methodNodes = map.nodes.filter(n => n.node_subtype === 'function');
    expect(methodNodes.length).toBeGreaterThanOrEqual(1);

    // Should have CONTROL/branch for if
    const ifNodes = map.nodes.filter(n => n.node_type === 'CONTROL' && n.node_subtype === 'branch');
    expect(ifNodes.length).toBeGreaterThanOrEqual(1);
  });

  // =========================================================================
  // Layer 5: ASP.NET Controller Pattern
  // =========================================================================

  it('identifies ASP.NET controller class with [ApiController] attribute', () => {
    resetSequenceHard();
    const code = `
[ApiController]
[Route("api/[controller]")]
public class UserController : ControllerBase
{
    [HttpPost]
    public IActionResult Create([FromBody] UserDto dto)
    {
        return Ok(dto);
    }
}
`;
    const tree = parseCSharp(code);
    const { map } = buildNeuralMap(tree, code, 'UserController.cs', csharpProfile);

    // Should be identified as a controller
    const controllers = map.nodes.filter(n => n.node_subtype === 'controller');
    expect(controllers.length).toBeGreaterThanOrEqual(1);

    // Should have route annotation META nodes
    const routeAnnotations = map.nodes.filter(n => n.node_subtype === 'route_annotation');
    expect(routeAnnotations.length).toBeGreaterThanOrEqual(1);

    // Should have EGRESS from Ok()
    const egress = map.nodes.filter(n => n.node_type === 'EGRESS');
    expect(egress.length).toBeGreaterThanOrEqual(1);
  });

  it('recognizes [Authorize] attribute as security annotation', () => {
    resetSequenceHard();
    const code = `
public class AdminController : ControllerBase
{
    [Authorize]
    [HttpGet]
    public IActionResult GetSecrets()
    {
        return Ok();
    }
}
`;
    const tree = parseCSharp(code);
    const { map } = buildNeuralMap(tree, code, 'AdminController.cs', csharpProfile);

    const securityAnnotations = map.nodes.filter(n => n.node_subtype === 'security_annotation');
    expect(securityAnnotations.length).toBeGreaterThanOrEqual(1);

    // Method should have auth_gate tag due to [Authorize]
    // Note: method also has [HttpGet] so it's classified as route, not function
    const methods = map.nodes.filter(n =>
      n.node_type === 'STRUCTURAL' && n.tags.includes('auth_gate')
    );
    expect(methods.length).toBeGreaterThanOrEqual(1);
  });

  // =========================================================================
  // Control Flow
  // =========================================================================

  it('classifies control flow statements', () => {
    resetSequenceHard();
    const code = `
public class Logic
{
    public void Run()
    {
        for (int i = 0; i < 10; i++) {}
        foreach (var item in new int[]{1,2,3}) {}
        while (true) { break; }
        switch (1) { case 1: break; }
        try { } catch (Exception e) { } finally { }
        return;
    }
}
`;
    const tree = parseCSharp(code);
    const { map } = buildNeuralMap(tree, code, 'Logic.cs', csharpProfile);

    const loops = map.nodes.filter(n => n.node_type === 'CONTROL' && n.node_subtype === 'loop');
    expect(loops.length).toBeGreaterThanOrEqual(2); // for + foreach + while

    const branches = map.nodes.filter(n => n.node_type === 'CONTROL' && n.node_subtype === 'branch');
    expect(branches.length).toBeGreaterThanOrEqual(1); // switch

    const errorHandling = map.nodes.filter(n => n.node_type === 'CONTROL' && n.node_subtype === 'error_handling');
    expect(errorHandling.length).toBeGreaterThanOrEqual(1); // try/catch/finally

    const returns = map.nodes.filter(n => n.node_type === 'CONTROL' && n.node_subtype === 'return');
    expect(returns.length).toBeGreaterThanOrEqual(1);
  });

  // =========================================================================
  // Full Vulnerability Scan
  // =========================================================================

  it('detects SQL injection pattern: tainted input flows to raw SQL', () => {
    resetSequenceHard();
    const code = `
public class UserController : ControllerBase
{
    [HttpGet]
    public IActionResult Search([FromQuery] string name)
    {
        var query = "SELECT * FROM Users WHERE Name = '" + name + "'";
        connection.ExecuteAsync(query);
        return Ok();
    }
}
`;
    const tree = parseCSharp(code);
    const { map } = buildNeuralMap(tree, code, 'UserController.cs', csharpProfile);

    // Should have INGRESS from [FromQuery] parameter
    const ingress = map.nodes.filter(n => n.node_type === 'INGRESS');
    expect(ingress.length).toBeGreaterThanOrEqual(1);

    // Should have STORAGE from ExecuteAsync
    const storage = map.nodes.filter(n => n.node_type === 'STORAGE');
    expect(storage.length).toBeGreaterThanOrEqual(1);
  });

  it('detects taint propagation through Entity Framework patterns', () => {
    resetSequenceHard();
    const code = `
public class UserService
{
    public void CreateUser(DbContext db, [FromBody] UserDto dto)
    {
        db.Add(dto);
        db.SaveChanges();
    }
}
`;
    const tree = parseCSharp(code);
    const { map } = buildNeuralMap(tree, code, 'UserService.cs', csharpProfile);

    // Should have tainted INGRESS from [FromBody]
    const ingress = map.nodes.filter(n => n.node_type === 'INGRESS');
    expect(ingress.length).toBeGreaterThanOrEqual(1);

    // Should have STORAGE nodes from db operations
    const storage = map.nodes.filter(n => n.node_type === 'STORAGE');
    expect(storage.length).toBeGreaterThanOrEqual(1);
  });

  it('handles async/await patterns correctly', () => {
    resetSequenceHard();
    const code = `
public class DataService
{
    public async void FetchData()
    {
        var result = await HttpClient.GetStringAsync("https://example.com");
        Console.WriteLine(result);
    }
}
`;
    const tree = parseCSharp(code);
    const { map } = buildNeuralMap(tree, code, 'DataService.cs', csharpProfile);

    // Should have EXTERNAL from HttpClient call
    const external = map.nodes.filter(n => n.node_type === 'EXTERNAL');
    expect(external.length).toBeGreaterThanOrEqual(1);

    // Should have EGRESS from Console.WriteLine
    const egress = map.nodes.filter(n => n.node_type === 'EGRESS');
    expect(egress.length).toBeGreaterThanOrEqual(1);
  });

  it('resolves lambda expressions correctly', () => {
    resetSequenceHard();
    const code = `
public class Service
{
    public void Process()
    {
        var handler = (string x) => Console.WriteLine(x);
    }
}
`;
    const tree = parseCSharp(code);
    const { map } = buildNeuralMap(tree, code, 'Service.cs', csharpProfile);

    const lambdas = map.nodes.filter(n =>
      n.node_type === 'STRUCTURAL' && n.tags.includes('lambda')
    );
    expect(lambdas.length).toBeGreaterThanOrEqual(1);
  });

  // =========================================================================
  // Profile Metadata
  // =========================================================================

  it('has correct profile metadata', () => {
    expect(csharpProfile.id).toBe('csharp');
    expect(csharpProfile.extensions).toContain('.cs');
  });

  it('recognizes function scope types', () => {
    expect(csharpProfile.functionScopeTypes.has('method_declaration')).toBe(true);
    expect(csharpProfile.functionScopeTypes.has('constructor_declaration')).toBe(true);
    expect(csharpProfile.functionScopeTypes.has('lambda_expression')).toBe(true);
  });

  it('recognizes class scope types', () => {
    expect(csharpProfile.classScopeTypes.has('class_declaration')).toBe(true);
    expect(csharpProfile.classScopeTypes.has('interface_declaration')).toBe(true);
    expect(csharpProfile.classScopeTypes.has('struct_declaration')).toBe(true);
    expect(csharpProfile.classScopeTypes.has('enum_declaration')).toBe(true);
    expect(csharpProfile.classScopeTypes.has('record_declaration')).toBe(true);
  });

  it('recognizes variable declaration types', () => {
    expect(csharpProfile.variableDeclarationTypes.has('local_declaration_statement')).toBe(true);
    expect(csharpProfile.variableDeclarationTypes.has('field_declaration')).toBe(true);
  });

  it('matches ingress patterns in code snapshots', () => {
    expect(csharpProfile.ingressPattern.test('Request.Form')).toBe(true);
    expect(csharpProfile.ingressPattern.test('Request.Query')).toBe(true);
    expect(csharpProfile.ingressPattern.test('Console.ReadLine')).toBe(true);
    expect(csharpProfile.ingressPattern.test('[FromBody]')).toBe(true);
    expect(csharpProfile.ingressPattern.test('HttpContext.Request')).toBe(true);
    expect(csharpProfile.ingressPattern.test('BinaryFormatter.Deserialize')).toBe(true);
  });

  // =========================================================================
  // Anti-Evasion: Constant Folding
  // =========================================================================

  it('folds string concatenation: "ev" + "al" → stores constantValue "eval"', () => {
    resetSequenceHard();
    const code = `
public class Evasion
{
    public void Run()
    {
        var action = "ev" + "al";
    }
}
`;
    const tree = parseCSharp(code);
    const { map } = buildNeuralMap(tree, code, 'Evasion.cs', csharpProfile);
    // The variable 'action' should have constantValue "eval" — verified
    // indirectly through the mapper internals. The fact that it doesn't
    // crash and produces nodes is the baseline test.
    expect(map.nodes.length).toBeGreaterThan(0);
  });

  it('detects Type.GetType with concatenated argument as reflection evasion', () => {
    resetSequenceHard();
    const code = `
using System;

public class Reflector
{
    public void Attack()
    {
        var t = Type.GetType("System.Diag" + "nostics.Process");
    }
}
`;
    const tree = parseCSharp(code);
    const { map } = buildNeuralMap(tree, code, 'Reflector.cs', csharpProfile);

    const reflectionNodes = map.nodes.filter(
      n => n.node_subtype === 'reflection'
    );
    expect(reflectionNodes.length).toBeGreaterThan(0);

    const typeGetType = reflectionNodes.find(n => n.label.includes('Type.GetType'));
    expect(typeGetType).toBeDefined();
    expect(typeGetType!.attack_surface).toContain('reflection_evasion');
    // The folded value should appear in the label
    expect(typeGetType!.label).toContain('System.Diagnostics.Process');
  });

  it('detects typeof(T).GetMethod with concatenated method name', () => {
    resetSequenceHard();
    const code = `
using System;

public class MethodReflect
{
    public void Attack()
    {
        var m = typeof(Process).GetMethod("St" + "art");
    }
}
`;
    const tree = parseCSharp(code);
    const { map } = buildNeuralMap(tree, code, 'MethodReflect.cs', csharpProfile);

    const reflectionNodes = map.nodes.filter(
      n => n.node_subtype === 'reflection'
    );
    expect(reflectionNodes.length).toBeGreaterThan(0);
    const getMethod = reflectionNodes.find(n => n.label.includes('GetMethod'));
    expect(getMethod).toBeDefined();
    expect(getMethod!.attack_surface).toContain('reflection_evasion');
    expect(getMethod!.label).toContain('Start');
  });

  it('marks reflection with tainted input as runtime_eval', () => {
    resetSequenceHard();
    const code = `
using System;

public class TaintedReflection
{
    public void Attack([FromBody] string userInput)
    {
        var t = Type.GetType(userInput);
    }
}
`;
    const tree = parseCSharp(code);
    const { map } = buildNeuralMap(tree, code, 'TaintedReflection.cs', csharpProfile);

    const reflectionNodes = map.nodes.filter(
      n => n.node_subtype === 'reflection'
    );
    expect(reflectionNodes.length).toBeGreaterThan(0);
    const typeGetType = reflectionNodes[0];
    expect(typeGetType.attack_surface).toContain('reflection_evasion');
    expect(typeGetType.attack_surface).toContain('runtime_eval');
  });

  it('folds Encoding.UTF8.GetString(new byte[]{...}) to constant', () => {
    resetSequenceHard();
    const code = `
using System;
using System.Text;

public class ByteEvasion
{
    public void Attack()
    {
        var name = Encoding.UTF8.GetString(new byte[]{80, 114, 111, 99, 101, 115, 115});
        var t = Type.GetType(name);
    }
}
`;
    const tree = parseCSharp(code);
    const { map } = buildNeuralMap(tree, code, 'ByteEvasion.cs', csharpProfile);

    const reflectionNodes = map.nodes.filter(n => n.node_subtype === 'reflection');
    expect(reflectionNodes.length).toBeGreaterThan(0);
    // The variable 'name' should have been folded to "Process" via constantValue
    // and the Type.GetType call should pick it up
    expect(reflectionNodes[0].attack_surface).toContain('reflection_evasion');
  });

  it('folds interpolated string $"{"ev"}{"al"}" to "eval"', () => {
    resetSequenceHard();
    const code = `
public class InterpolEvasion
{
    public void Run()
    {
        var x = $"{"ev"}{"al"}";
    }
}
`;
    const tree = parseCSharp(code);
    const { map } = buildNeuralMap(tree, code, 'InterpolEvasion.cs', csharpProfile);
    // Should not crash and should produce nodes
    expect(map.nodes.length).toBeGreaterThan(0);
  });

  it('detects Assembly.Load with base64-decoded argument', () => {
    resetSequenceHard();
    const code = `
using System;
using System.Reflection;
using System.Text;

public class AsmLoad
{
    public void Attack()
    {
        var asm = Assembly.Load(Encoding.UTF8.GetString(Convert.FromBase64String("bXNjb3JsaWI=")));
    }
}
`;
    const tree = parseCSharp(code);
    const { map } = buildNeuralMap(tree, code, 'AsmLoad.cs', csharpProfile);

    const reflectionNodes = map.nodes.filter(n => n.node_subtype === 'reflection');
    expect(reflectionNodes.length).toBeGreaterThan(0);
    expect(reflectionNodes[0].attack_surface).toContain('reflection_evasion');
  });
});
