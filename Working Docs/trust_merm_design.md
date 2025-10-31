# TRUST System Design - Mermaid Diagrams

This document contains Mermaid diagrams that represent the supervisor hierarchy, component relationships, and data flow through the TRUST (Trusted Remote Unified Secure Transport) system.

## Table of Contents

1. [Supervisor Hierarchy](#supervisor-hierarchy)
2. [Component Relationships](#component-relationships)
3. [Connection Lifecycle](#connection-lifecycle)
4. [Data Flow Diagrams](#data-flow-diagrams)
5. [FSM State Transitions](#fsm-state-transitions)
6. [RPC Request Processing](#rpc-request-processing)

---

## Supervisor Hierarchy

### Complete Supervision Tree

```mermaid
graph TD
    Root[semp_sup<br/>one_for_one<br/>intensity: 5/10s] --> ListenerSup[trust_listener_sup<br/>rest_for_one<br/>intensity: 5/10s]
    
    ListenerSup --> ConnSup[trust_conn_sup<br/>DynamicSupervisor<br/>one_for_one<br/>intensity: 50/10s]
    ListenerSup --> Listener[trust_listener<br/>gen_server<br/>permanent]
    
    ConnSup --> FSM1[trust_conn_fsm<br/>gen_statem<br/>temporary]
    ConnSup --> FSM2[trust_conn_fsm<br/>gen_statem<br/>temporary]
    ConnSup --> FSM3[trust_conn_fsm<br/>gen_statem<br/>temporary]
    
    FSM1 --> WorkerSup1[trust_conn_worker_sup<br/>DynamicSupervisor<br/>one_for_one<br/>intensity: 10/5s]
    FSM2 --> WorkerSup2[trust_conn_worker_sup<br/>DynamicSupervisor<br/>one_for_one<br/>intensity: 10/5s]
    
    WorkerSup1 --> RPC1[trust_rpc_worker<br/>gen_server<br/>temporary]
    WorkerSup1 --> RPC2[trust_rpc_worker<br/>gen_server<br/>temporary]
    WorkerSup2 --> RPC3[trust_rpc_worker<br/>gen_server<br/>temporary]
    
    classDef supervisor fill:#e1f5fe,stroke:#01579b,stroke-width:2px
    classDef fsm fill:#f3e5f5,stroke:#4a148c,stroke-width:2px
    classDef worker fill:#e8f5e8,stroke:#1b5e20,stroke-width:2px
    
    class Root,ListenerSup,ConnSup,WorkerSup1,WorkerSup2 supervisor
    class FSM1,FSM2,FSM3 fsm
    class Listener,RPC1,RPC2,RPC3 worker
```

### Supervisor Strategies and Restart Policies

```mermaid
graph LR
    subgraph "Restart Strategies"
        A[one_for_one<br/>Restart only failed child] 
        B[rest_for_one<br/>Restart failed child and all after it]
        C[DynamicSupervisor<br/>Dynamic child management]
    end
    
    subgraph "Restart Policies"
        D[permanent<br/>Always restart]
        E[temporary<br/>Never restart]
        F[transient<br/>Restart only on abnormal exit]
    end
    
    subgraph "Intensity Settings"
        G[5/10s<br/>Max 5 restarts in 10s]
        H[50/10s<br/>Max 50 restarts in 10s]
        I[10/5s<br/>Max 10 restarts in 5s]
    end
```

---

## Component Relationships

### Core Components and Dependencies

```mermaid
graph TB
    subgraph "Application Layer"
        App[semp_app] --> Sup[semp_sup]
    end
    
    subgraph "Trust Layer"
        Sup --> ListenerSup[trust_listener_sup]
        ListenerSup --> ConnSup[trust_conn_sup]
        ListenerSup --> Listener[trust_listener]
        
        ConnSup --> FSM[trust_conn_fsm]
        FSM --> WorkerSup[trust_conn_worker_sup]
        WorkerSup --> RPCWorker[trust_rpc_worker]
    end
    
    subgraph "Supporting Services"
        Whitelist[semp_whitelist]
        Suspicion[trust_suspicion]
        Token[trust_token]
        Facades[semp_facades]
        TRPC[trpc]
    end
    
    subgraph "External Dependencies"
        SSL[SSL/TLS]
        ETS[ETS Tables]
        Timer[Timers]
    end
    
    Listener --> SSL
    FSM --> Whitelist
    FSM --> Suspicion
    FSM --> Token
    FSM --> Facades
    FSM --> WorkerSup
    RPCWorker --> TRPC
    Suspicion --> ETS
    Token --> ETS
    Whitelist --> ETS
    FSM --> Timer
    
    classDef app fill:#ffecb3,stroke:#f57f17,stroke-width:2px
    classDef trust fill:#e8f5e8,stroke:#2e7d32,stroke-width:2px
    classDef support fill:#f3e5f5,stroke:#7b1fa2,stroke-width:2px
    classDef external fill:#ffebee,stroke:#c62828,stroke-width:2px
    
    class App,Sup app
    class ListenerSup,ConnSup,Listener,FSM,WorkerSup,RPCWorker trust
    class Whitelist,Suspicion,Token,Facades,TRPC support
    class SSL,ETS,Timer external
```

### Process Communication Patterns

```mermaid
graph LR
    subgraph "Client-Server Communication"
        C[Client] -->|TLS 1.3| L[trust_listener]
        L -->|spawn| FSM[trust_conn_fsm]
        FSM -->|cast| RPC[trust_rpc_worker]
        RPC -->|reply| FSM
        FSM -->|response| C
    end
    
    subgraph "Internal Communication"
        FSM -->|monitor| WS[trust_conn_worker_sup]
        WS -->|start_child| RPC
        RPC -->|'DOWN'| FSM
        FSM -->|gen_statem:cast| FSM
    end
    
    subgraph "Supervisor Communication"
        CS[trust_conn_sup] -->|start_child| FSM
        LS[trust_listener_sup] -->|start_child| CS
        LS -->|start_child| L
    end
```

---

## Connection Lifecycle

### TLS Connection Establishment

```mermaid
sequenceDiagram
    participant C as Client
    participant L as trust_listener
    participant CS as trust_conn_sup
    participant FSM as trust_conn_fsm
    participant W as semp_whitelist
    participant S as trust_suspicion
    participant T as trust_token
    
    C->>L: TCP Connect
    L->>L: TLS Handshake (ALPN: trust/1)
    L->>CS: start_child(trust_conn_fsm)
    CS->>FSM: start_link(Socket, PeerInfo, Config)
    FSM->>FSM: init() → handshake_token state
    
    Note over FSM: Extract client cert → SHA512 fingerprint
    FSM->>W: is_allowed(fingerprint)
    W-->>FSM: true/false
    
    alt Whitelisted
        FSM->>S: is_trusted(fingerprint)
        S-->>FSM: true/false
        
        alt Trusted
            FSM->>T: validate(token, fingerprint)
            T-->>FSM: ok/{error, reason}
            
            alt Valid Token
                FSM->>FSM: transition_to_active()
                FSM-->>C: Ready for requests
            else Invalid Token
                FSM->>FSM: send_goaway() → closing
                FSM-->>C: Close connection
            end
        else Quarantined
            FSM->>FSM: Close silently
        end
    else Not Whitelisted
        FSM->>FSM: Close silently
    end
```

### Connection Termination

```mermaid
sequenceDiagram
    participant FSM as trust_conn_fsm
    participant WS as trust_conn_worker_sup
    participant RPC as trust_rpc_worker
    participant CS as trust_conn_sup
    participant L as trust_listener
    
    Note over FSM: Termination triggers
    Note over FSM: - Idle timeout
    Note over FSM: - Max age timeout
    Note over FSM: - Protocol error
    Note over FSM: - Client disconnect
    
    FSM->>FSM: Enter closing state
    FSM->>FSM: send_goaway()
    FSM->>FSM: semp_facades:close(socket)
    
    par Wait for workers to complete
        FSM->>WS: Monitor workers
        WS->>RPC: Terminate workers
        RPC-->>WS: Worker completed
        WS-->>FSM: All workers done
    and Or timeout
        FSM->>FSM: Drain timeout reached
    end
    
    FSM->>FSM: terminate() → stop normal
    FSM-->>CS: Process exits
    CS-->>L: Connection cleaned up
```

---

## Data Flow Diagrams

### Request Processing Flow

```mermaid
flowchart TD
    Start([Client Request]) --> TLS{TLS Connection?}
    TLS -->|No| Reject[Reject Connection]
    TLS -->|Yes| Cert[Extract Client Certificate]
    
    Cert --> FP[Generate SHA512 Fingerprint]
    FP --> WL{Whitelist Check}
    WL -->|Not Allowed| Reject
    WL -->|Allowed| Sus{Trust Check}
    
    Sus -->|Quarantined| Reject
    Sus -->|Trusted| Token{Token Validation}
    Token -->|Invalid| Reject
    Token -->|Valid| Active[FSM Active State]
    
    Active --> Decode[Decode Request Frame]
    Decode --> ValidFrame{Valid Frame?}
    ValidFrame -->|No| ProtocolError[Protocol Error]
    ValidFrame -->|Yes| Perms{Permissions Check}
    
    Perms -->|Denied| Reject
    Perms -->|Allowed| SpawnWorker[Spawn RPC Worker]
    SpawnWorker --> Execute[Execute MFA]
    
    Execute --> Success{Success?}
    Success -->|Yes| Response[Send Response]
    Success -->|No| Error[Log Error & Close]
    
    Response --> Close[Close Connection]
    ProtocolError --> Close
    Error --> Close
    Reject --> Close
    
    Close --> End([End])
```

### Multiplexed Request Handling

```mermaid
sequenceDiagram
    participant C as Client
    participant FSM as trust_conn_fsm
    participant WS as trust_conn_worker_sup
    participant W1 as RPC Worker 1
    participant W2 as RPC Worker 2
    participant W3 as RPC Worker 3
    
    Note over FSM: Active state, max_inflight=3
    
    C->>FSM: Request 1 (call)
    FSM->>WS: start_child(worker1)
    WS->>W1: start_link(MFA1)
    FSM-->>C: Processing...
    
    C->>FSM: Request 2 (cast)
    FSM->>WS: start_child(worker2)
    WS->>W2: start_link(MFA2)
    Note over FSM: No response for cast
    
    C->>FSM: Request 3 (call)
    FSM->>WS: start_child(worker3)
    WS->>W3: start_link(MFA3)
    FSM-->>C: Processing...
    
    C->>FSM: Request 4 (call)
    Note over FSM: Backpressure: max_inflight reached
    FSM-->>C: GOAWAY (backpressure)
    
    par Parallel Processing
        W1->>W1: Execute MFA1
        W1-->>FSM: Result 1
        FSM-->>C: Response 1
    and
        W2->>W2: Execute MFA2
        W2-->>FSM: Complete
        Note over FSM: No response for cast
    and
        W3->>W3: Execute MFA3
        W3-->>FSM: Result 3
        FSM-->>C: Response 3
    end
    
    Note over FSM: All workers complete
    FSM->>FSM: Close connection
```

---

## FSM State Transitions

### Connection FSM State Machine

```mermaid
stateDiagram-v2
    [*] --> handshake_token: start_link()
    
    handshake_token --> active: valid token + permissions
    handshake_token --> closing: invalid token/protocol error
    
    active --> active: valid request (within limits)
    active --> draining: max_calls reached OR explicit drain
    active --> closing: protocol error/timeout/backpressure
    
    draining --> closing: inflight == 0 OR drain_timeout
    draining --> draining: inflight > 0 (wait for workers)
    
    closing --> [*]: terminate()
    
    note right of handshake_token
        - Extract client cert → fingerprint
        - Whitelist check
        - Trust/suspicion check
        - Token validation
    end note
    
    note right of active
        - Process RPC requests
        - Spawn workers (max_inflight)
        - Handle backpressure
        - Monitor idle/max_age timers
    end note
    
    note right of draining
        - Wait for inflight workers
        - Send GOAWAY
        - Prepare for graceful shutdown
    end note
    
    note right of closing
        - Send GOAWAY if not sent
        - Close socket
        - Cleanup resources
        - Terminate process
    end note
```

### FSM Event Handling

```mermaid
graph TD
    subgraph "Event Types"
        E1[cast: {ssl, Socket, Bin}]
        E2[info: idle_timeout]
        E3[info: max_age_timeout]
        E4[info: {'DOWN', Pid, Reason}]
        E5[enter: state_name]
    end
    
    subgraph "State Handlers"
        H1[handle_handshake_token/3]
        H2[handle_active_request/3]
        H3[handle_draining_wait/3]
        H4[handle_closing_cleanup/3]
    end
    
    subgraph "Actions"
        A1[spawn_worker/2]
        A2[send_goaway/3]
        A3[semp_facades:close/1]
        A4[reset_idle_timer/1]
        A5[trust_suspicion:bump/2]
    end
    
    E1 --> H1
    E1 --> H2
    E2 --> H1
    E2 --> H2
    E3 --> H1
    E3 --> H2
    E4 --> H2
    E5 --> H4
    
    H1 --> A1
    H1 --> A2
    H1 --> A3
    H1 --> A4
    H2 --> A1
    H2 --> A2
    H2 --> A3
    H2 --> A4
    H2 --> A5
    H3 --> A2
    H3 --> A3
    H4 --> A3
```

---

## RPC Request Processing

### Worker Lifecycle

```mermaid
sequenceDiagram
    participant FSM as trust_conn_fsm
    participant WS as trust_conn_worker_sup
    participant W as trust_rpc_worker
    participant TRPC as trpc
    participant Client as Client Process
    
    FSM->>FSM: Receive request frame
    FSM->>FSM: Decode request
    FSM->>FSM: Check permissions
    
    FSM->>WS: start_child(WorkerSpec)
    WS->>W: start_link(FsmPid, ReqId, Type, MFA, Args)
    W->>W: init() → execute_rpc()
    
    W->>TRPC: apply(M, F, Args)
    TRPC->>Client: Execute user code
    
    alt Call Request
        Client-->>TRPC: Return value
        TRPC-->>W: {ok, Result}
        W->>FSM: Send result frame
        FSM-->>Client: Response frame
    else Cast Request
        Client-->>TRPC: Execute (no return)
        TRPC-->>W: {ok, ok}
        W->>W: Complete (no response)
    end
    
    W->>W: terminate() → stop normal
    W-->>WS: Worker exits
    WS-->>FSM: 'DOWN' message
    FSM->>FSM: Decrement inflight counter
```

### Error Handling and Recovery

```mermaid
flowchart TD
    Start([RPC Request]) --> Validate[Validate Request]
    Validate --> Valid{Valid?}
    Valid -->|No| Error1[Protocol Error]
    Valid -->|Yes| Perms[Check Permissions]
    
    Perms --> Allowed{Allowed?}
    Allowed -->|No| Error2[Permission Denied]
    Allowed -->|Yes| Spawn[Spawn Worker]
    
    Spawn --> Success{Worker Started?}
    Success -->|No| Error3[Worker Start Failed]
    Success -->|Yes| Execute[Execute MFA]
    
    Execute --> Result{Execution Result}
    Result -->|Success| Send[Send Response]
    Result -->|Exception| Error4[Execution Error]
    Result -->|Timeout| Error5[Timeout]
    
    Error1 --> Log1[Log Error]
    Error2 --> Log2[Log Error]
    Error3 --> Log3[Log Error]
    Error4 --> Log4[Log Error]
    Error5 --> Log5[Log Error]
    
    Log1 --> Sus1[trust_suspicion:bump]
    Log2 --> Sus2[trust_suspicion:bump]
    Log3 --> Sus3[trust_suspicion:bump]
    Log4 --> Sus4[trust_suspicion:bump]
    Log5 --> Sus5[trust_suspicion:bump]
    
    Sus1 --> Close[Close Connection]
    Sus2 --> Close
    Sus3 --> Close
    Sus4 --> Close
    Sus5 --> Close
    
    Send --> Complete[Request Complete]
    Complete --> End([End])
    Close --> End
```

---

## System Architecture Overview

### High-Level System View

```mermaid
graph TB
    subgraph "Client Side"
        C[TRUST Client]
        CTLS[Client TLS]
    end
    
    subgraph "Network"
        N[TCP/TLS 1.3]
    end
    
    subgraph "Server Side"
        subgraph "Application Layer"
            APP[semp_app]
            SUP[semp_sup]
        end
        
        subgraph "Trust Layer"
            LS[trust_listener_sup]
            CS[trust_conn_sup]
            L[trust_listener]
            FSM[trust_conn_fsm]
            WS[trust_conn_worker_sup]
            W[trust_rpc_worker]
        end
        
        subgraph "Security Layer"
            WL[semp_whitelist]
            SUS[trust_suspicion]
            TOK[trust_token]
        end
        
        subgraph "Transport Layer"
            FAC[semp_facades]
            SSL[SSL/TLS]
        end
        
        subgraph "Business Logic"
            TRPC[trpc]
            USER[User Code]
        end
    end
    
    C --> CTLS
    CTLS --> N
    N --> SSL
    SSL --> FAC
    FAC --> L
    L --> FSM
    FSM --> WL
    FSM --> SUS
    FSM --> TOK
    FSM --> WS
    WS --> W
    W --> TRPC
    TRPC --> USER
    
    APP --> SUP
    SUP --> LS
    LS --> CS
    LS --> L
    CS --> FSM
    
    classDef client fill:#e3f2fd,stroke:#1976d2,stroke-width:2px
    classDef server fill:#f3e5f5,stroke:#7b1fa2,stroke-width:2px
    classDef security fill:#e8f5e8,stroke:#388e3c,stroke-width:2px
    classDef transport fill:#fff3e0,stroke:#f57c00,stroke-width:2px
    classDef business fill:#fce4ec,stroke:#c2185b,stroke-width:2px
    
    class C,CTLS client
    class APP,SUP,LS,CS,L,FSM,WS,W server
    class WL,SUS,TOK security
    class FAC,SSL transport
    class TRPC,USER business
```

This comprehensive design document provides a complete view of the TRUST system architecture, showing how supervisors manage processes, how data flows through the system, and how the various components interact to provide secure, multiplexed RPC communication.
