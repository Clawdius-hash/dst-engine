/**
 * Phoneme Expansion: Java — Jakarta EE / Java EE patterns
 *
 * Scope: JSF managed beans, CDI injection, EJB remote interfaces, JMS message listeners
 *
 * 10 entries covering:
 *   - JSF: FacesContext.getExternalContext, ExternalContext.getRequestParameterMap (INGRESS)
 *   - JMS: MessageListener.onMessage, TextMessage.getText (INGRESS),
 *          JMSProducer.send (EGRESS), JMSConsumer.receive (INGRESS)
 *   - CDI: Instance.select, BeanManager.getReference (STRUCTURAL)
 *   - EJB: EJBContext.lookup (EXTERNAL), SessionContext.getBusinessObject (EXTERNAL)
 *
 * All functions are real Jakarta EE / Java EE APIs.
 * Security relevance:
 *   - JSF entries expose HTTP request data through the JSF abstraction layer
 *   - JMS entries handle untrusted message payloads (deserialization surface)
 *   - CDI entries control runtime dependency resolution (injection attacks)
 *   - EJB entries enable JNDI lookups and remote interface resolution
 */

import type { NodeType } from '../types.js';

export interface CalleePattern {
  nodeType: NodeType;
  subtype: string;
  tainted: boolean;
}

export const JAKARTA_EE_ENTRIES: Record<string, CalleePattern> = {

  // ── JSF (JavaServer Faces) ────────────────────────────────────────────
  // FacesContext.getExternalContext() returns ExternalContext — the bridge
  // from JSF to the underlying servlet container. Through it, attackers reach
  // request params, headers, cookies, session — everything.
  'FacesContext.getExternalContext':       { nodeType: 'INGRESS',    subtype: 'jsf_request',    tainted: true },

  // ExternalContext.getRequestParameterMap() — direct user input wrapped by JSF.
  // Equivalent to HttpServletRequest.getParameterMap() but accessed through JSF layer.
  'ExternalContext.getRequestParameterMap': { nodeType: 'INGRESS',   subtype: 'jsf_request',    tainted: true },

  // ── JMS (Java Message Service) ────────────────────────────────────────
  // MessageListener.onMessage() — the entry point for message-driven beans.
  // Any class implementing javax.jms.MessageListener or jakarta.jms.MessageListener
  // receives untrusted message payloads here. Classic deserialization attack surface.
  'MessageListener.onMessage':             { nodeType: 'INGRESS',    subtype: 'jms_receive',    tainted: true },

  // TextMessage.getText() — extracts the string payload from a JMS TextMessage.
  // The content is attacker-controlled if the message source is untrusted.
  'TextMessage.getText':                   { nodeType: 'INGRESS',    subtype: 'jms_receive',    tainted: true },

  // JMSProducer.send() — Jakarta JMS 2.0+ API for sending messages to a destination.
  // Data leaving the system to a message broker (ActiveMQ, RabbitMQ, etc.).
  'JMSProducer.send':                      { nodeType: 'EGRESS',     subtype: 'jms_send',       tainted: false },

  // JMSConsumer.receive() — synchronous blocking receive from a JMS destination.
  // Returns a Message object containing untrusted payload data.
  'JMSConsumer.receive':                   { nodeType: 'INGRESS',    subtype: 'jms_receive',    tainted: true },

  // ── CDI (Contexts and Dependency Injection) ───────────────────────────
  // Instance.select() — programmatic CDI bean lookup. Used when @Inject alone
  // isn't sufficient (e.g., selecting among @Qualifier-annotated alternatives).
  // Controls which implementation gets wired at runtime — topology decision.
  'Instance.select':                       { nodeType: 'STRUCTURAL', subtype: 'cdi_injection',  tainted: false },

  // BeanManager.getReference() — low-level CDI API for obtaining contextual
  // bean references. Used in extensions and framework code. Controls dependency graph.
  'BeanManager.getReference':              { nodeType: 'STRUCTURAL', subtype: 'cdi_injection',  tainted: false },

  // ── EJB (Enterprise JavaBeans) ────────────────────────────────────────
  // EJBContext.lookup() — JNDI-based resource lookup from within an EJB.
  // Same JNDI attack surface as InitialContext.lookup but scoped to the EJB environment.
  // Can resolve DataSources, JMS resources, remote EJB stubs, etc.
  'EJBContext.lookup':                     { nodeType: 'EXTERNAL',   subtype: 'jndi_lookup',    tainted: true },

  // SessionContext.getBusinessObject() — obtains a reference to the current
  // EJB's business interface. Used to pass remote/local references to other components.
  // Structural: defines how EJB topology is wired for remote access.
  'SessionContext.getBusinessObject':      { nodeType: 'EXTERNAL',   subtype: 'ejb_remote',     tainted: false },
};
