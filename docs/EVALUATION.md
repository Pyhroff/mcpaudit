# mcpaudit Evaluation Methodology

## Goal

Measure detector behavior on a controlled corpus rather than making universal claims about MCP security.

## Evaluation layers

### 1. Unit correctness

Each detector should have positive and negative fixtures covering:

- obvious malicious descriptions
- benign security-sensitive descriptions
- narrow and broad permission schemas
- unchanged and modified manifests
- benign and malicious tool-output fixtures

### 2. Regression corpus

Maintain a versioned corpus with labels:

```
fixture_id, detector, expected_severity, rationale
```

Every new detector or rule should add both positive and negative cases.

### 3. Metrics

For a labeled corpus report:

- TP, FP, TN, FN
- precision
- recall
- F1
- false-positive rate
- severity confusion matrix

Do not report a metric without the corpus size and fixture definition.

### 4. Dynamic evaluation

For confused-deputy experiments record:

- model/adapter
- target tool
- attack fixture
- prompt wrapper
- number of trials
- successful influence count
- failure modes
- model/API version

Dynamic results should be reported as experimental evidence, not as a universal model vulnerability rate.

## Reproducibility contract

A benchmark result should be reproducible from:

1. repository commit
2. fixture corpus version
3. scanner version
4. configuration/policy
5. model identifier, when applicable
6. trial count and random seed, when applicable

## Recommended release gate

Before calling a release benchmark-ready:

- run the complete test suite
- run the labeled regression corpus
- inspect all false positives
- inspect all false negatives
- publish the corpus definition
- document known blind spots

## Interpretation

A higher score is not automatically a better security product. Detection coverage, false-positive cost, runtime cost, explainability, and reproducibility all matter.
