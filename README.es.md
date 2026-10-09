<div align="center">

# RepoDoctor

**Scanner rápido de salud de repositorios y cadena de suministro para desarrolladores.**

[![CI](https://github.com/DevPooks/repodoctor/actions/workflows/ci.yml/badge.svg)](https://github.com/DevPooks/repodoctor/actions/workflows/ci.yml)
[![Go](https://img.shields.io/badge/Go-1.23+-00ADD8?logo=go&logoColor=white)](go.mod)
[![Licencia: MIT](https://img.shields.io/badge/Licencia-MIT-2ea44f.svg)](LICENSE)

[English](README.md) · [Español](README.es.md)

</div>

RepoDoctor inspecciona un repositorio local sin instalar dependencias ni ejecutar código del proyecto. Combina datos públicos de advisories con chequeos estáticos de procedencia, nombres sospechosos, scripts de instalación, secretos probables, archivos de higiene, CI, tests y mantenibilidad.

## Por qué RepoDoctor

Un repositorio moderno puede confiar en cientos de paquetes antes de ejecutar su propia lógica. Una versión vulnerable, un nombre mal escrito o un `postinstall` inesperado cruza esa frontera de confianza durante una instalación común. Además, una guía o asistente de programación puede sugerir un nombre plausible que no existe.

RepoDoctor permite revisar esas señales antes de instalar. No certifica que un paquete sea seguro: presenta evidencia concreta para tomar una decisión.

## Funcionalidad implementada

- npm: `package.json`, `package-lock.json`, `npm-shrinkwrap.json`.
- Python: `requirements.txt`, `pyproject.toml`, `poetry.lock`.
- Go: `go.mod`.
- Versiones exactas desde lockfiles y rangos mutables desde manifests.
- OSV por lotes y registros maliciosos de OpenSSF con formato OSV.
- Existencia y antigüedad de paquetes npm/PyPI.
- Heurística de typosquatting con distancia de edición, sin etiquetar malware automáticamente.
- Dependencias desde Git, GitHub, rutas locales o URLs directas.
- Inspección estática de scripts npm de instalación.
- Búsqueda local y conservadora de secretos con previews redactados.
- README, licencia, `.gitignore`, `SECURITY.md`, CI, tests y artefactos trackeados.
- Archivos fuente grandes y comentarios `TODO`/`FIXME`.
- Salida de texto/JSON y códigos de salida estables para CI.

## Seguridad por diseño

RepoDoctor nunca instala paquetes, importa módulos del repositorio, ejecuta scripts, abre binarios, explota vulnerabilidades, analiza malware dinámicamente ni modifica el proyecto escaneado. El contenido del repositorio no se sube a servicios externos.

OSV recibe solamente ecosistema, nombre y versión exacta. npm/PyPI reciben nombres de paquetes directos. `--offline` desactiva ambas consultas.

## Instalación y uso

```bash
git clone https://github.com/DevPooks/repodoctor.git
cd repodoctor
make build

./bin/repodoctor scan .
./bin/repodoctor scan . --format json
./bin/repodoctor scan . --ci
./bin/repodoctor security . --offline
./bin/repodoctor explain RD-SEC-004
```

## Comandos

| Comando | Alcance |
|---|---|
| `scan` | Dependencias, seguridad, salud y calidad |
| `deps` | Extracción, procedencia y pinning |
| `security` | OSV, registry, secretos y scripts |
| `health` | Archivos, Git, tests, CI y calidad |
| `explain` | Explicación y acción para un finding |
| `version` | Versión del binario |

## Configuración

`.repodoctor.yml`:

```yaml
ignore:
  packages:
    - paquete-interno-revisado
  paths:
    - testdata

rules:
  large_file_lines: 500
  package_age_warning_days: 14

security:
  osv: true
  registry_metadata: true
  secret_scan: true

severity_overrides:
  RD-HEALTH-003: low

ignore_findings:
  - RD-SEC-006:paquete-ejemplo
```

Las supresiones no son silenciosas: el reporte siempre indica cuántos findings fueron omitidos.

## Códigos de salida

| Código | Significado |
|---:|---|
| `0` | Sin findings bloqueantes |
| `1` | Advertencias medium/low |
| `2` | Finding high/critical |
| `3` | Fallo del scan, configuración o salida |

## Evidencia frente a heurísticas

Una vulnerabilidad o paquete malicioso conocido necesita un registro de OSV/OpenSSF. La similitud de nombre, ausencia del registry y antigüedad son señales para revisión, no veredictos. Un fallo de red queda como `unavailable`, nunca como “sin vulnerabilidades”.

Consulta el [modelo de amenazas](docs/threat-model.md), el [catálogo de findings](docs/finding-codes.md) y las [notas para entrevistas](docs/interview-notes.md).

## Límites actuales

- Los parsers cubren formatos comunes, no todas las extensiones de cada package manager.
- Los metadatos de registry están centrados en npm/PyPI.
- Aún no existe caché local de advisories.
- El detector de secretos prioriza precisión y no reemplaza una plataforma DLP.
- La lista de nombres comunes para similitud es pequeña e intencionalmente explicable.

## Desarrollo

```bash
make check
make test-race
make scan
```

Las APIs externas se simulan con `httptest`; la suite no depende de servicios públicos y los fixtures no contienen malware funcional.

## Licencia

MIT © 2026 DevPooks
