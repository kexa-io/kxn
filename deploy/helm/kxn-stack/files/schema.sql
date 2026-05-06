--
-- PostgreSQL database dump
--

\restrict ee7T8XvCGzlcX1Rvcx4p06PvFBCIsZdVEYFosd8x7TC2G3c5n41UWxUBfXTehBs

-- Dumped from database version 18.3
-- Dumped by pg_dump version 18.3

SET statement_timeout = 0;
SET lock_timeout = 0;
SET idle_in_transaction_session_timeout = 0;
SET transaction_timeout = 0;
SET client_encoding = 'UTF8';
SET standard_conforming_strings = on;
SELECT pg_catalog.set_config('search_path', '', false);
SET check_function_bodies = false;
SET xmloption = content;
SET client_min_messages = warning;
SET row_security = off;

--
-- Name: public; Type: SCHEMA; Schema: -; Owner: -
--

-- *not* creating schema, since initdb creates it


SET default_tablespace = '';

SET default_table_access_method = heap;

--
-- Name: disk_usage; Type: TABLE; Schema: public; Owner: -
--

CREATE TABLE IF NOT EXISTS public.disk_usage (
    id bigint NOT NULL,
    "time" timestamp with time zone NOT NULL,
    node character varying(255) NOT NULL,
    resource_kind character varying(32) NOT NULL,
    namespace character varying(255),
    pvc_name character varying(255),
    storage_class character varying(255),
    capacity_bytes bigint,
    used_bytes bigint,
    available_bytes bigint
);


--
-- Name: disk_usage_id_seq; Type: SEQUENCE; Schema: public; Owner: -
--

CREATE SEQUENCE IF NOT EXISTS public.disk_usage_id_seq
    START WITH 1
    INCREMENT BY 1
    NO MINVALUE
    NO MAXVALUE
    CACHE 1;


--
-- Name: disk_usage_id_seq; Type: SEQUENCE OWNED BY; Schema: public; Owner: -
--

ALTER SEQUENCE public.disk_usage_id_seq OWNED BY public.disk_usage.id;


--
-- Name: geo_ip_cache; Type: TABLE; Schema: public; Owner: -
--

CREATE TABLE IF NOT EXISTS public.geo_ip_cache (
    ip inet NOT NULL,
    country character varying(64),
    city character varying(255),
    lat double precision,
    lon double precision,
    resolved_at timestamp with time zone DEFAULT now()
);


--
-- Name: k8s_jobs; Type: TABLE; Schema: public; Owner: -
--

CREATE TABLE IF NOT EXISTS public.k8s_jobs (
    id bigint NOT NULL,
    "time" timestamp with time zone NOT NULL,
    namespace character varying(255) NOT NULL,
    name character varying(255) NOT NULL,
    cronjob character varying(255),
    succeeded integer,
    failed integer,
    start_time timestamp with time zone,
    completion_time timestamp with time zone,
    duration_seconds integer,
    status character varying(32)
);


--
-- Name: k8s_jobs_id_seq; Type: SEQUENCE; Schema: public; Owner: -
--

CREATE SEQUENCE IF NOT EXISTS public.k8s_jobs_id_seq
    START WITH 1
    INCREMENT BY 1
    NO MINVALUE
    NO MAXVALUE
    CACHE 1;


--
-- Name: k8s_jobs_id_seq; Type: SEQUENCE OWNED BY; Schema: public; Owner: -
--

ALTER SEQUENCE public.k8s_jobs_id_seq OWNED BY public.k8s_jobs.id;


--
-- Name: logs; Type: TABLE; Schema: public; Owner: -
--

CREATE TABLE IF NOT EXISTS public.logs (
    id bigint NOT NULL,
    "time" timestamp with time zone NOT NULL,
    target character varying(255) NOT NULL,
    source character varying(64) NOT NULL,
    level character varying(32) NOT NULL,
    message text NOT NULL,
    host character varying(255),
    unit character varying(255),
    batch_id character varying(255),
    tags jsonb DEFAULT '{}'::jsonb
);


--
-- Name: logs_id_seq; Type: SEQUENCE; Schema: public; Owner: -
--

CREATE SEQUENCE IF NOT EXISTS public.logs_id_seq
    START WITH 1
    INCREMENT BY 1
    NO MINVALUE
    NO MAXVALUE
    CACHE 1;


--
-- Name: logs_id_seq; Type: SEQUENCE OWNED BY; Schema: public; Owner: -
--

ALTER SEQUENCE public.logs_id_seq OWNED BY public.logs.id;


--
-- Name: metrics; Type: TABLE; Schema: public; Owner: -
--

CREATE TABLE IF NOT EXISTS public.metrics (
    "time" timestamp with time zone NOT NULL,
    target character varying(255) NOT NULL,
    provider character varying(255) NOT NULL,
    resource_type character varying(255) NOT NULL,
    metric_name character varying(255) NOT NULL,
    value_num double precision,
    value_str text
);


--
-- Name: netpol_coverage; Type: TABLE; Schema: public; Owner: -
--

CREATE TABLE IF NOT EXISTS public.netpol_coverage (
    id bigint NOT NULL,
    "time" timestamp with time zone NOT NULL,
    namespace character varying(255) NOT NULL,
    netpol_count integer NOT NULL,
    has_default_deny boolean NOT NULL
);


--
-- Name: netpol_coverage_id_seq; Type: SEQUENCE; Schema: public; Owner: -
--

CREATE SEQUENCE IF NOT EXISTS public.netpol_coverage_id_seq
    START WITH 1
    INCREMENT BY 1
    NO MINVALUE
    NO MAXVALUE
    CACHE 1;


--
-- Name: netpol_coverage_id_seq; Type: SEQUENCE OWNED BY; Schema: public; Owner: -
--

ALTER SEQUENCE public.netpol_coverage_id_seq OWNED BY public.netpol_coverage.id;


--
-- Name: origins; Type: TABLE; Schema: public; Owner: -
--

CREATE TABLE IF NOT EXISTS public.origins (
    id integer NOT NULL,
    name character varying(255) NOT NULL,
    description text
);


--
-- Name: origins_id_seq; Type: SEQUENCE; Schema: public; Owner: -
--

CREATE SEQUENCE IF NOT EXISTS public.origins_id_seq
    AS integer
    START WITH 1
    INCREMENT BY 1
    NO MINVALUE
    NO MAXVALUE
    CACHE 1;


--
-- Name: origins_id_seq; Type: SEQUENCE OWNED BY; Schema: public; Owner: -
--

ALTER SEQUENCE public.origins_id_seq OWNED BY public.origins.id;


--
-- Name: pod_resource; Type: TABLE; Schema: public; Owner: -
--

CREATE TABLE IF NOT EXISTS public.pod_resource (
    id bigint NOT NULL,
    "time" timestamp with time zone NOT NULL,
    namespace character varying(255) NOT NULL,
    pod character varying(255) NOT NULL,
    container character varying(255) NOT NULL,
    cpu_millicores double precision,
    memory_mib double precision
);


--
-- Name: pod_resource_id_seq; Type: SEQUENCE; Schema: public; Owner: -
--

CREATE SEQUENCE IF NOT EXISTS public.pod_resource_id_seq
    START WITH 1
    INCREMENT BY 1
    NO MINVALUE
    NO MAXVALUE
    CACHE 1;


--
-- Name: pod_resource_id_seq; Type: SEQUENCE OWNED BY; Schema: public; Owner: -
--

ALTER SEQUENCE public.pod_resource_id_seq OWNED BY public.pod_resource.id;


--
-- Name: provider_items; Type: TABLE; Schema: public; Owner: -
--

CREATE TABLE IF NOT EXISTS public.provider_items (
    id integer NOT NULL,
    name character varying(255),
    provider_id integer
);


--
-- Name: provider_items_id_seq; Type: SEQUENCE; Schema: public; Owner: -
--

CREATE SEQUENCE IF NOT EXISTS public.provider_items_id_seq
    AS integer
    START WITH 1
    INCREMENT BY 1
    NO MINVALUE
    NO MAXVALUE
    CACHE 1;


--
-- Name: provider_items_id_seq; Type: SEQUENCE OWNED BY; Schema: public; Owner: -
--

ALTER SEQUENCE public.provider_items_id_seq OWNED BY public.provider_items.id;


--
-- Name: providers; Type: TABLE; Schema: public; Owner: -
--

CREATE TABLE IF NOT EXISTS public.providers (
    id integer NOT NULL,
    name character varying(255) NOT NULL
);


--
-- Name: providers_id_seq; Type: SEQUENCE; Schema: public; Owner: -
--

CREATE SEQUENCE IF NOT EXISTS public.providers_id_seq
    AS integer
    START WITH 1
    INCREMENT BY 1
    NO MINVALUE
    NO MAXVALUE
    CACHE 1;


--
-- Name: providers_id_seq; Type: SEQUENCE OWNED BY; Schema: public; Owner: -
--

ALTER SEQUENCE public.providers_id_seq OWNED BY public.providers.id;


--
-- Name: request_geo; Type: TABLE; Schema: public; Owner: -
--

CREATE TABLE IF NOT EXISTS public.request_geo (
    id bigint NOT NULL,
    "time" timestamp with time zone NOT NULL,
    client_ip inet NOT NULL,
    status integer NOT NULL,
    method character varying(16),
    host character varying(255),
    path text,
    duration_ms integer,
    country character varying(64),
    city character varying(255),
    lat double precision,
    lon double precision
);


--
-- Name: request_geo_id_seq; Type: SEQUENCE; Schema: public; Owner: -
--

CREATE SEQUENCE IF NOT EXISTS public.request_geo_id_seq
    START WITH 1
    INCREMENT BY 1
    NO MINVALUE
    NO MAXVALUE
    CACHE 1;


--
-- Name: request_geo_id_seq; Type: SEQUENCE OWNED BY; Schema: public; Owner: -
--

ALTER SEQUENCE public.request_geo_id_seq OWNED BY public.request_geo.id;


--
-- Name: resources; Type: TABLE; Schema: public; Owner: -
--

CREATE TABLE IF NOT EXISTS public.resources (
    id integer NOT NULL,
    content jsonb NOT NULL,
    created_at timestamp with time zone DEFAULT now(),
    origin_id integer,
    provider_item_id integer
);


--
-- Name: resources_id_seq; Type: SEQUENCE; Schema: public; Owner: -
--

CREATE SEQUENCE IF NOT EXISTS public.resources_id_seq
    AS integer
    START WITH 1
    INCREMENT BY 1
    NO MINVALUE
    NO MAXVALUE
    CACHE 1;


--
-- Name: resources_id_seq; Type: SEQUENCE OWNED BY; Schema: public; Owner: -
--

ALTER SEQUENCE public.resources_id_seq OWNED BY public.resources.id;


--
-- Name: rules; Type: TABLE; Schema: public; Owner: -
--

CREATE TABLE IF NOT EXISTS public.rules (
    id integer NOT NULL,
    name character varying(255) NOT NULL,
    description text,
    level integer,
    provider_id integer,
    provider_item_id integer
);


--
-- Name: rules_id_seq; Type: SEQUENCE; Schema: public; Owner: -
--

CREATE SEQUENCE IF NOT EXISTS public.rules_id_seq
    AS integer
    START WITH 1
    INCREMENT BY 1
    NO MINVALUE
    NO MAXVALUE
    CACHE 1;


--
-- Name: rules_id_seq; Type: SEQUENCE OWNED BY; Schema: public; Owner: -
--

ALTER SEQUENCE public.rules_id_seq OWNED BY public.rules.id;


--
-- Name: scans; Type: TABLE; Schema: public; Owner: -
--

CREATE TABLE IF NOT EXISTS public.scans (
    id integer NOT NULL,
    created_at timestamp with time zone DEFAULT now(),
    error boolean,
    messages jsonb,
    conditions jsonb,
    resource_id integer,
    rule_id integer,
    batch_id character varying(255),
    target character varying(255)
);


--
-- Name: scans_id_seq; Type: SEQUENCE; Schema: public; Owner: -
--

CREATE SEQUENCE IF NOT EXISTS public.scans_id_seq
    AS integer
    START WITH 1
    INCREMENT BY 1
    NO MINVALUE
    NO MAXVALUE
    CACHE 1;


--
-- Name: scans_id_seq; Type: SEQUENCE OWNED BY; Schema: public; Owner: -
--

ALTER SEQUENCE public.scans_id_seq OWNED BY public.scans.id;


--
-- Name: tags; Type: TABLE; Schema: public; Owner: -
--

CREATE TABLE IF NOT EXISTS public.tags (
    id integer NOT NULL,
    name character varying(255),
    value text,
    scan_id integer
);


--
-- Name: tags_id_seq; Type: SEQUENCE; Schema: public; Owner: -
--

CREATE SEQUENCE IF NOT EXISTS public.tags_id_seq
    AS integer
    START WITH 1
    INCREMENT BY 1
    NO MINVALUE
    NO MAXVALUE
    CACHE 1;


--
-- Name: tags_id_seq; Type: SEQUENCE OWNED BY; Schema: public; Owner: -
--

ALTER SEQUENCE public.tags_id_seq OWNED BY public.tags.id;


--
-- Name: tls_certs; Type: TABLE; Schema: public; Owner: -
--

CREATE TABLE IF NOT EXISTS public.tls_certs (
    id bigint NOT NULL,
    "time" timestamp with time zone NOT NULL,
    namespace character varying(255) NOT NULL,
    secret_name character varying(255) NOT NULL,
    common_name character varying(255),
    san text,
    issuer character varying(255),
    not_after timestamp with time zone,
    days_left integer
);


--
-- Name: tls_certs_id_seq; Type: SEQUENCE; Schema: public; Owner: -
--

CREATE SEQUENCE IF NOT EXISTS public.tls_certs_id_seq
    START WITH 1
    INCREMENT BY 1
    NO MINVALUE
    NO MAXVALUE
    CACHE 1;


--
-- Name: tls_certs_id_seq; Type: SEQUENCE OWNED BY; Schema: public; Owner: -
--

ALTER SEQUENCE public.tls_certs_id_seq OWNED BY public.tls_certs.id;


--
-- Name: disk_usage id; Type: DEFAULT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.disk_usage ALTER COLUMN id SET DEFAULT nextval('public.disk_usage_id_seq'::regclass);


--
-- Name: k8s_jobs id; Type: DEFAULT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.k8s_jobs ALTER COLUMN id SET DEFAULT nextval('public.k8s_jobs_id_seq'::regclass);


--
-- Name: logs id; Type: DEFAULT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.logs ALTER COLUMN id SET DEFAULT nextval('public.logs_id_seq'::regclass);


--
-- Name: netpol_coverage id; Type: DEFAULT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.netpol_coverage ALTER COLUMN id SET DEFAULT nextval('public.netpol_coverage_id_seq'::regclass);


--
-- Name: origins id; Type: DEFAULT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.origins ALTER COLUMN id SET DEFAULT nextval('public.origins_id_seq'::regclass);


--
-- Name: pod_resource id; Type: DEFAULT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.pod_resource ALTER COLUMN id SET DEFAULT nextval('public.pod_resource_id_seq'::regclass);


--
-- Name: provider_items id; Type: DEFAULT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.provider_items ALTER COLUMN id SET DEFAULT nextval('public.provider_items_id_seq'::regclass);


--
-- Name: providers id; Type: DEFAULT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.providers ALTER COLUMN id SET DEFAULT nextval('public.providers_id_seq'::regclass);


--
-- Name: request_geo id; Type: DEFAULT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.request_geo ALTER COLUMN id SET DEFAULT nextval('public.request_geo_id_seq'::regclass);


--
-- Name: resources id; Type: DEFAULT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.resources ALTER COLUMN id SET DEFAULT nextval('public.resources_id_seq'::regclass);


--
-- Name: rules id; Type: DEFAULT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.rules ALTER COLUMN id SET DEFAULT nextval('public.rules_id_seq'::regclass);


--
-- Name: scans id; Type: DEFAULT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.scans ALTER COLUMN id SET DEFAULT nextval('public.scans_id_seq'::regclass);


--
-- Name: tags id; Type: DEFAULT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.tags ALTER COLUMN id SET DEFAULT nextval('public.tags_id_seq'::regclass);


--
-- Name: tls_certs id; Type: DEFAULT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.tls_certs ALTER COLUMN id SET DEFAULT nextval('public.tls_certs_id_seq'::regclass);


--
-- Name: disk_usage disk_usage_pkey; Type: CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.disk_usage
    ADD CONSTRAINT disk_usage_pkey PRIMARY KEY (id);


--
-- Name: geo_ip_cache geo_ip_cache_pkey; Type: CONSTRAINT; Schema: public; Owner: -
--

-- ALTER TABLE ONLY public.geo_ip_cache
--     ADD CONSTRAINT geo_ip_cache_pkey PRIMARY KEY (ip);


--
-- Name: k8s_jobs k8s_jobs_pkey; Type: CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.k8s_jobs
    ADD CONSTRAINT k8s_jobs_pkey PRIMARY KEY (id);


--
-- Name: logs logs_pkey; Type: CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.logs
    ADD CONSTRAINT logs_pkey PRIMARY KEY (id);


--
-- Name: netpol_coverage netpol_coverage_pkey; Type: CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.netpol_coverage
    ADD CONSTRAINT netpol_coverage_pkey PRIMARY KEY (id);


--
-- Name: origins origins_name_key; Type: CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.origins
    ADD CONSTRAINT origins_name_key UNIQUE (name);


--
-- Name: origins origins_pkey; Type: CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.origins
    ADD CONSTRAINT origins_pkey PRIMARY KEY (id);


--
-- Name: pod_resource pod_resource_pkey; Type: CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.pod_resource
    ADD CONSTRAINT pod_resource_pkey PRIMARY KEY (id);


--
-- Name: provider_items provider_items_name_provider_id_key; Type: CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.provider_items
    ADD CONSTRAINT provider_items_name_provider_id_key UNIQUE (name, provider_id);


--
-- Name: provider_items provider_items_pkey; Type: CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.provider_items
    ADD CONSTRAINT provider_items_pkey PRIMARY KEY (id);


--
-- Name: providers providers_name_key; Type: CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.providers
    ADD CONSTRAINT providers_name_key UNIQUE (name);


--
-- Name: providers providers_pkey; Type: CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.providers
    ADD CONSTRAINT providers_pkey PRIMARY KEY (id);


--
-- Name: request_geo request_geo_pkey; Type: CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.request_geo
    ADD CONSTRAINT request_geo_pkey PRIMARY KEY (id);


--
-- Name: resources resources_pkey; Type: CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.resources
    ADD CONSTRAINT resources_pkey PRIMARY KEY (id);


--
-- Name: rules rules_name_key; Type: CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.rules
    ADD CONSTRAINT rules_name_key UNIQUE (name);


--
-- Name: rules rules_pkey; Type: CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.rules
    ADD CONSTRAINT rules_pkey PRIMARY KEY (id);


--
-- Name: scans scans_pkey; Type: CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.scans
    ADD CONSTRAINT scans_pkey PRIMARY KEY (id);


--
-- Name: tags tags_pkey; Type: CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.tags
    ADD CONSTRAINT tags_pkey PRIMARY KEY (id);


--
-- Name: tls_certs tls_certs_pkey; Type: CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.tls_certs
    ADD CONSTRAINT tls_certs_pkey PRIMARY KEY (id);


--
-- Name: idx_disk_usage_namespace; Type: INDEX; Schema: public; Owner: -
--

CREATE INDEX IF NOT EXISTS idx_disk_usage_namespace ON public.disk_usage USING btree (namespace);


--
-- Name: idx_disk_usage_node; Type: INDEX; Schema: public; Owner: -
--

CREATE INDEX IF NOT EXISTS idx_disk_usage_node ON public.disk_usage USING btree (node);


--
-- Name: idx_disk_usage_time; Type: INDEX; Schema: public; Owner: -
--

CREATE INDEX IF NOT EXISTS idx_disk_usage_time ON public.disk_usage USING btree ("time");


--
-- Name: idx_k8s_jobs_ns; Type: INDEX; Schema: public; Owner: -
--

CREATE INDEX IF NOT EXISTS idx_k8s_jobs_ns ON public.k8s_jobs USING btree (namespace, cronjob);


--
-- Name: idx_k8s_jobs_time; Type: INDEX; Schema: public; Owner: -
--

CREATE INDEX IF NOT EXISTS idx_k8s_jobs_time ON public.k8s_jobs USING btree ("time");


--
-- Name: idx_logs_target_level; Type: INDEX; Schema: public; Owner: -
--

CREATE INDEX IF NOT EXISTS idx_logs_target_level ON public.logs USING btree (target, level);


--
-- Name: idx_logs_time; Type: INDEX; Schema: public; Owner: -
--

CREATE INDEX IF NOT EXISTS idx_logs_time ON public.logs USING btree ("time");


--
-- Name: idx_metrics_name; Type: INDEX; Schema: public; Owner: -
--

CREATE INDEX IF NOT EXISTS idx_metrics_name ON public.metrics USING btree (target, resource_type, metric_name);


--
-- Name: idx_metrics_target; Type: INDEX; Schema: public; Owner: -
--

CREATE INDEX IF NOT EXISTS idx_metrics_target ON public.metrics USING btree (target);


--
-- Name: idx_metrics_time; Type: INDEX; Schema: public; Owner: -
--

CREATE INDEX IF NOT EXISTS idx_metrics_time ON public.metrics USING btree ("time");


--
-- Name: idx_netpol_coverage_time; Type: INDEX; Schema: public; Owner: -
--

CREATE INDEX IF NOT EXISTS idx_netpol_coverage_time ON public.netpol_coverage USING btree ("time");


--
-- Name: idx_pod_resource_ns; Type: INDEX; Schema: public; Owner: -
--

CREATE INDEX IF NOT EXISTS idx_pod_resource_ns ON public.pod_resource USING btree (namespace);


--
-- Name: idx_pod_resource_time; Type: INDEX; Schema: public; Owner: -
--

CREATE INDEX IF NOT EXISTS idx_pod_resource_time ON public.pod_resource USING btree ("time");


--
-- Name: idx_request_geo_country; Type: INDEX; Schema: public; Owner: -
--

CREATE INDEX IF NOT EXISTS idx_request_geo_country ON public.request_geo USING btree (country);


--
-- Name: idx_request_geo_status; Type: INDEX; Schema: public; Owner: -
--

CREATE INDEX IF NOT EXISTS idx_request_geo_status ON public.request_geo USING btree (status);


--
-- Name: idx_request_geo_time; Type: INDEX; Schema: public; Owner: -
--

CREATE INDEX IF NOT EXISTS idx_request_geo_time ON public.request_geo USING btree ("time");


--
-- Name: idx_scans_batch_id; Type: INDEX; Schema: public; Owner: -
--

CREATE INDEX IF NOT EXISTS idx_scans_batch_id ON public.scans USING btree (batch_id);


--
-- Name: idx_scans_created_at; Type: INDEX; Schema: public; Owner: -
--

CREATE INDEX IF NOT EXISTS idx_scans_created_at ON public.scans USING btree (created_at);


--
-- Name: idx_scans_error; Type: INDEX; Schema: public; Owner: -
--

CREATE INDEX IF NOT EXISTS idx_scans_error ON public.scans USING btree (error);


--
-- Name: idx_scans_target; Type: INDEX; Schema: public; Owner: -
--

CREATE INDEX IF NOT EXISTS idx_scans_target ON public.scans USING btree (target);


--
-- Name: idx_tls_certs_days_left; Type: INDEX; Schema: public; Owner: -
--

CREATE INDEX IF NOT EXISTS idx_tls_certs_days_left ON public.tls_certs USING btree (days_left);


--
-- Name: idx_tls_certs_time; Type: INDEX; Schema: public; Owner: -
--

CREATE INDEX IF NOT EXISTS idx_tls_certs_time ON public.tls_certs USING btree ("time");


--
-- Name: provider_items provider_items_provider_id_fkey; Type: FK CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.provider_items
    ADD CONSTRAINT provider_items_provider_id_fkey FOREIGN KEY (provider_id) REFERENCES public.providers(id);


--
-- Name: resources resources_origin_id_fkey; Type: FK CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.resources
    ADD CONSTRAINT resources_origin_id_fkey FOREIGN KEY (origin_id) REFERENCES public.origins(id);


--
-- Name: resources resources_provider_item_id_fkey; Type: FK CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.resources
    ADD CONSTRAINT resources_provider_item_id_fkey FOREIGN KEY (provider_item_id) REFERENCES public.provider_items(id);


--
-- Name: rules rules_provider_id_fkey; Type: FK CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.rules
    ADD CONSTRAINT rules_provider_id_fkey FOREIGN KEY (provider_id) REFERENCES public.providers(id);


--
-- Name: rules rules_provider_item_id_fkey; Type: FK CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.rules
    ADD CONSTRAINT rules_provider_item_id_fkey FOREIGN KEY (provider_item_id) REFERENCES public.provider_items(id);


--
-- Name: scans scans_resource_id_fkey; Type: FK CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.scans
    ADD CONSTRAINT scans_resource_id_fkey FOREIGN KEY (resource_id) REFERENCES public.resources(id);


--
-- Name: scans scans_rule_id_fkey; Type: FK CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.scans
    ADD CONSTRAINT scans_rule_id_fkey FOREIGN KEY (rule_id) REFERENCES public.rules(id);


--
-- Name: tags tags_scan_id_fkey; Type: FK CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.tags
    ADD CONSTRAINT tags_scan_id_fkey FOREIGN KEY (scan_id) REFERENCES public.scans(id);


--
-- PostgreSQL database dump complete
--

\unrestrict ee7T8XvCGzlcX1Rvcx4p06PvFBCIsZdVEYFosd8x7TC2G3c5n41UWxUBfXTehBs
