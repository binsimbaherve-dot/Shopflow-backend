# ShopFlow



A South African e-commerce marketplace for space-saving and multi-functional furniture --- Murphy beds, wall-mounted folding desks, drop-leaf tables, lift-storage beds, modular convertible pieces, and more. Built as a full-stack SDET portfolio project with an integrated DevSecOps pipeline.



## Security



![SAST](https://github.com/binsimbaherve-dot/Shopflow-backend/actions/workflows/sast.yml/badge.svg)

![Quality Gate Status](https://sonarcloud.io/api/project_badges/measure?project=binsimbaherve-dot_Shopflow-backend&metric=alert_status)

[![Security Policy](https://img.shields.io/badge/security-policy-blue.svg)](./SECURITY.md)



See [SECURITY.md](./SECURITY.md) for our vulnerability disclosure policy, and [THREAT_MODEL.md](./THREAT_MODEL.md) for the STRIDE threat model.



## Product Overview



ShopFlow targets high-LSM South African consumers (Gauteng, Western Cape, KZN) buying configurable furniture with made-to-order production and white-glove delivery. Products have variants (size, finish, fabric) with per-variant pricing and lead times. Orders move through an expanded state machine: pending, paid, in_production, ready_for_dispatch, delivery_scheduled, out_for_delivery, delivered, and optionally assembled.



Average order value: R3,000 - R45,000.



## Tech Stack



| Layer | Technology |

| ----- | ---------- |

| Backend | Spring Boot (Java 17), MySQL |

| Frontend | React |

| Payments | Stripe |

| Containerization | Docker, Docker Compose |

| CI/CD | GitHub Actions |

| SAST | SonarCloud, Semgrep |

| SCA | Snyk, Dependabot |

| DAST | OWASP ZAP |

| Container Scanning | Trivy |

| Secret Scanning | GitLeaks |



## Architecture



- **Variant data model** --- products have configurable variants (size x finish x fabric) with per-variant pricing, SKU, and lead time

- **Bifurcated stock logic** --- in-stock items decrement traditional stock; made-to-order items reserve production capacity slots

- **Delivery scheduling** --- slot capacity per zone per day, race-condition-safe reservation with optimistic locking

- **Expanded order state machine** --- see Product Overview above



## Related Repositories



- Backend (this repo) - Spring Boot REST API

- [Online-platform-frontend](https://github.com/binsimbaherve-dot/Online-platform-frontend) - React UI

- [selenium-ui-automation-framework](https://github.com/binsimbaherve-dot/-Java-Selenium-UI-Automation-Framework) - Selenium + Cucumber E2E tests

- [rest-api-automation-framework](https://github.com/binsimbaherve-dot/rest-api-automation-framework-backend-testing) - REST Assured API tests

- [Database-Validation-Automation-SQL-Java](https://github.com/binsimbaherve-dot/Database-Validation-Automation-SQL-Java) - JDBC/MySQL data validation

- bdd-cucumber-e2e-framework - Cucumber + Appium mobile testing

- mobile-test-automation-csharp - C# Appium native Android automation



## Setup



Setup instructions will be added as the backend build progresses through Month 1 of the build plan.



## Status



This project is in active pre-launch development (Week 0 - Security Sprint).


