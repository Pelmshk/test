-- ============================================================
-- Схема реляционной БД инцидентов ИБ в космических системах
-- СУБД: SQLite (переносима на PostgreSQL без существенных изменений)
-- Версия таксономии: 1.0.0 | Дата среза данных: 2026-10-24
-- Файл загружается скриптом scripts/01_create_db.R через DBI::dbExecute
-- ============================================================

PRAGMA journal_mode = WAL;
PRAGMA foreign_keys = ON;

-- ---------- Справочники (версионируемая типология) ----------

-- Целевые сегменты космических систем
CREATE TABLE IF NOT EXISTS dict_segment (
    segment_code TEXT PRIMARY KEY,   -- напр. 'SEG-TTC'
    name         TEXT NOT NULL,
    description  TEXT
);

-- Векторы атаки с маппингом на внешние фреймворки
CREATE TABLE IF NOT EXISTS dict_vector (
    vector_code   TEXT PRIMARY KEY,  -- напр. 'V-JAM'
    name          TEXT NOT NULL,
    mitre_atlas   TEXT,              -- код техники Space MITRE ATLAS
    mitre_attack  TEXT,              -- техника MITRE ATT&CK
    veris_family  TEXT               -- семейство VERIS
);

-- Классы орбит
CREATE TABLE IF NOT EXISTS dict_orbit (
    orbit_code TEXT PRIMARY KEY,      -- 'LEO','MEO','GEO','HEO','DEEPSPACE','GROUND','UNKNOWN'
    name       TEXT NOT NULL
);

-- Типы космических аппаратов
CREATE TABLE IF NOT EXISTS dict_sat_type (
    sat_type_code TEXT PRIMARY KEY,
    name          TEXT NOT NULL
);

-- Уровни достоверности
CREATE TABLE IF NOT EXISTS dict_confidence (
    confidence_code TEXT PRIMARY KEY, -- 'verified','single_source','disputed','rumor'
    min_sources     INTEGER NOT NULL, -- минимальное число независимых источников
    description     TEXT
);

-- Журнал версий таксономии (обязательное условие воспроизводимости)
CREATE TABLE IF NOT EXISTS taxonomy_versions (
    taxonomy_version TEXT PRIMARY KEY,
    release_date     TEXT NOT NULL,   -- ISO-8601
    changes          TEXT NOT NULL    -- описание изменений относительно предыдущей версии
);

-- ---------- Основные сущности ----------

-- Космические аппараты / системы (нормализация: один объект — одна запись)
CREATE TABLE IF NOT EXISTS assets (
    asset_id    INTEGER PRIMARY KEY AUTOINCREMENT,
    name        TEXT NOT NULL UNIQUE,      -- 'Viasat KA-SAT', 'GPS III SV05', ...
    operator    TEXT,                      -- оператор/владелец
    country     TEXT,                      -- ISO-3166 alpha-2
    sat_type    TEXT REFERENCES dict_sat_type(sat_type_code),
    orbit_class TEXT REFERENCES dict_orbit(orbit_code),
    notes       TEXT
);

-- Источники OSINT (публикации, advisories, новости, реестры)
CREATE TABLE IF NOT EXISTS sources (
    source_id     INTEGER PRIMARY KEY AUTOINCREMENT,
    url           TEXT NOT NULL UNIQUE,
    publisher     TEXT NOT NULL,           -- 'CISA','NASA','SpaceNews','MITRE',...
    source_type   TEXT NOT NULL CHECK (source_type IN
                   ('advisory','cve','news','report','official_statement','blog','dataset')),
    published_at  TEXT,                    -- ISO-8601 дата публикации
    accessed_at   TEXT NOT NULL,           -- ISO-8601 дата обращения (срез!)
    reliability   TEXT CHECK (reliability IN ('high','medium','low')),
    title         TEXT
);

-- Инциденты (ядро базы)
CREATE TABLE IF NOT EXISTS incidents (
    incident_id     INTEGER PRIMARY KEY AUTOINCREMENT,
    external_ref    TEXT UNIQUE,           -- 'INC-2022-0001' — стабильный бизнес-ключ
    event_date      TEXT,                  -- ISO-8601 дата события (или начало окна)
    event_date_end  TEXT,                  -- для длящихся событий (кампаний глушения)
    date_precision  TEXT NOT NULL DEFAULT 'day'
                    CHECK (date_precision IN ('exact','month','year','approx')),
    title           TEXT NOT NULL,
    summary         TEXT,                  -- аннотация по материалам источников
    target_segment  TEXT NOT NULL REFERENCES dict_segment(segment_code),
    orbit_class     TEXT REFERENCES dict_orbit(orbit_code),
    impact_level    INTEGER CHECK (impact_level BETWEEN 0 AND 5),
    impact_desc     TEXT,                  -- narrative: что произошло с миссией
    confidence      TEXT NOT NULL REFERENCES dict_confidence(confidence_code),
    attribution     TEXT,                  -- предполагаемый исполнитель (или 'unknown')
    attribution_conf TEXT CHECK (attribution_conf IN ('confirmed','likely','claimed','unknown')),
    country_origin  TEXT,                  -- ISO-3166 подозреваемой стороны (если заявлено)
    location_lat    REAL,                  -- география (для leaflet на этапе EDA)
    location_lon    REAL,
    location_name   TEXT,
    inclusion_ok    INTEGER NOT NULL DEFAULT 1 CHECK (inclusion_ok IN (0,1)), -- прошёл C1–C4
    exclusion_reason TEXT,                 -- если inclusion_ok = 0
    taxonomy_version TEXT NOT NULL REFERENCES taxonomy_versions(taxonomy_version),
    created_at      TEXT NOT NULL DEFAULT (datetime('now')),
    reviewed_by     TEXT,                  -- инициалы второго верификатора (двойная проверка)
    review_status   TEXT NOT NULL DEFAULT 'pending'
                    CHECK (review_status IN ('pending','approved','rejected'))
);

-- Связь инцидент ↔ аппарат (многие-ко-многим: кампания может затрагивать группировку)
CREATE TABLE IF NOT EXISTS incident_assets (
    incident_id INTEGER NOT NULL REFERENCES incidents(incident_id) ON DELETE CASCADE,
    asset_id    INTEGER NOT NULL REFERENCES assets(asset_id)       ON DELETE CASCADE,
    role        TEXT NOT NULL DEFAULT 'primary' CHECK (role IN ('primary','affected','adjacent')),
    PRIMARY KEY (incident_id, asset_id)
);

-- Связь инцидент ↔ вектор атаки (многие-ко-многим: hybrid-атаки)
CREATE TABLE IF NOT EXISTS incident_vectors (
    incident_id INTEGER NOT NULL REFERENCES incidents(incident_id) ON DELETE CASCADE,
    vector_code TEXT NOT NULL REFERENCES dict_vector(vector_code),
    is_primary  INTEGER NOT NULL DEFAULT 0 CHECK (is_primary IN (0,1)),
    evidence    TEXT,                       -- цитата/ссылка, обосновывающая вектор
    PRIMARY KEY (incident_id, vector_code)
);

-- Подтверждающие источники инцидента (требование: >=2 для verified)
CREATE TABLE IF NOT EXISTS incident_sources (
    incident_id INTEGER NOT NULL REFERENCES incidents(incident_id) ON DELETE CASCADE,
    source_id   INTEGER NOT NULL REFERENCES sources(source_id)     ON DELETE CASCADE,
    independence_group TEXT,               -- одинаковый group = не независимы (перепечатки)
    PRIMARY KEY (incident_id, source_id)
);

-- Уязвимости (CVE) как отдельная сущность, связанная с инцидентами
CREATE TABLE IF NOT EXISTS vulnerabilities (
    cve_id       TEXT PRIMARY KEY,          -- 'CVE-2022-33885' (SONiK)
    cvss_score   REAL,
    kev_flag     INTEGER DEFAULT 0 CHECK (kev_flag IN (0,1)), -- в каталоге CISA KEV?
    component    TEXT                       -- затронутый компонент/стек
);

CREATE TABLE IF NOT EXISTS incident_vulnerabilities (
    incident_id INTEGER NOT NULL REFERENCES incidents(incident_id) ON DELETE CASCADE,
    cve_id      TEXT NOT NULL REFERENCES vulnerabilities(cve_id)   ON DELETE CASCADE,
    PRIMARY KEY (incident_id, cve_id)
);

-- Сырой корпус упоминаний (этап 2: до разметки; обеспечивает прослеживаемость)
CREATE TABLE IF NOT EXISTS corpus_mentions (
    mention_id  INTEGER PRIMARY KEY AUTOINCREMENT,
    source_id   INTEGER REFERENCES sources(source_id),
    raw_text    TEXT NOT NULL,
    extracted_entities TEXT,                -- JSON: извлечённые NER-сущности
    mapped_incident_id INTEGER REFERENCES incidents(incident_id), -- результат Linking
    nlp_pipeline_ver TEXT
);

-- Аудит изменений (воспроизводимость ручных правок)
CREATE TABLE IF NOT EXISTS audit_log (
    audit_id    INTEGER PRIMARY KEY AUTOINCREMENT,
    changed_at  TEXT NOT NULL DEFAULT (datetime('now')),
    table_name  TEXT NOT NULL,
    record_key  TEXT NOT NULL,
    field_name  TEXT,
    old_value   TEXT,
    new_value   TEXT,
    actor       TEXT
);

-- ---------- Представления для аналитики ----------

-- Инциденты с агрегированными векторами и числом независимых источников
CREATE VIEW IF NOT EXISTS v_incidents_enriched AS
SELECT
    i.incident_id,
    i.external_ref,
    substr(i.event_date, 1, 4)                       AS year,
    i.event_date,
    i.title,
    i.target_segment,
    i.orbit_class,
    i.impact_level,
    i.confidence,
    i.taxonomy_version,
    group_concat(DISTINCT iv.vector_code)            AS vectors,
    count(DISTINCT isr.source_id)                    AS n_sources,
    count(DISTINCT CASE WHEN isr.independence_group IS NOT NULL
          THEN isr.independence_group END)           AS n_independent_sources
FROM incidents i
LEFT JOIN incident_vectors     iv  ON iv.incident_id  = i.incident_id
LEFT JOIN incident_sources     isr ON isr.incident_id = i.incident_id
WHERE i.inclusion_ok = 1
GROUP BY i.incident_id;

-- Матрица «вектор × сегмент» для тепловых карт рисков
CREATE VIEW IF NOT EXISTS v_matrix_vector_segment AS
SELECT
    substr(i.event_date, 1, 4)  AS year,
    i.target_segment,
    iv.vector_code,
    i.confidence,
    COUNT(*)                    AS n_incidents,
    AVG(i.impact_level)         AS avg_impact
FROM incidents i
JOIN incident_vectors iv ON iv.incident_id = i.incident_id
WHERE i.inclusion_ok = 1
GROUP BY year, i.target_segment, iv.vector_code, i.confidence;

-- Контроль требования двойной верификации: verified требует >=2 независимых источников
CREATE VIEW IF NOT EXISTS v_verification_audit AS
SELECT
    i.incident_id,
    i.external_ref,
    i.confidence,
    COUNT(DISTINCT s.independence_group) AS independent_groups,
    CASE
      WHEN i.confidence = 'verified'
       AND COUNT(DISTINCT s.independence_group) < 2
      THEN 'VIOLATION: verified with <2 independent sources'
      ELSE 'ok'
    END AS check_result
FROM incidents i
LEFT JOIN incident_sources s ON s.incident_id = i.incident_id
GROUP BY i.incident_id;

-- ---------- Индексы ----------
CREATE INDEX IF NOT EXISTS idx_incidents_date     ON incidents(event_date);
CREATE INDEX IF NOT EXISTS idx_incidents_segment  ON incidents(target_segment);
CREATE INDEX IF NOT EXISTS idx_incidents_conf     ON incidents(confidence);
CREATE INDEX IF NOT EXISTS idx_vectors_vector     ON incident_vectors(vector_code);
CREATE INDEX IF NOT EXISTS idx_sources_published  ON sources(published_at);
