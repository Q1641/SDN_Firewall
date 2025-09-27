--
-- PostgreSQL database cluster dump
--

\restrict GL4kKySkdwkDiP9Q5Bb8JtZgdk1KNU6waN3iUWPj2c8JJDuPBgn1qjjyhKp9RWQ

SET default_transaction_read_only = off;

SET client_encoding = 'UTF8';
SET standard_conforming_strings = on;

--
-- Roles
--

CREATE ROLE postgres;
ALTER ROLE postgres WITH SUPERUSER INHERIT CREATEROLE CREATEDB LOGIN REPLICATION BYPASSRLS;
CREATE ROLE srv_acc;
ALTER ROLE srv_acc WITH NOSUPERUSER INHERIT NOCREATEROLE CREATEDB LOGIN NOREPLICATION NOBYPASSRLS PASSWORD 'SCRAM-SHA-256$4096:zL9B8zKZNIx0bQD5yVPUhg==$SlenZcYQhI6SyZqWto9rmlWmdCpF6HHChElc5wUi5bM=:qkejAF8+ioGIt4jUKbl641BnRh3k49aHmX4/VRizBrM=';
CREATE ROLE srv_backend;
ALTER ROLE srv_backend WITH NOSUPERUSER INHERIT NOCREATEROLE NOCREATEDB LOGIN NOREPLICATION NOBYPASSRLS PASSWORD 'SCRAM-SHA-256$4096:UT1D0KTWXRwAaLZzNMMh0A==$ieQNhnFEauRrsQF6XAWNMjmjJqrlCrB5mQTV153Nlq8=:OtmYXXpqLF82qfibMwwe8HDjHS+DW/lMwQJhhQXmYHg=';

--
-- User Configurations
--

--
-- User Config "srv_backend"
--

ALTER ROLE srv_backend SET search_path TO 'sdnfw';








\unrestrict GL4kKySkdwkDiP9Q5Bb8JtZgdk1KNU6waN3iUWPj2c8JJDuPBgn1qjjyhKp9RWQ

--
-- Databases
--

--
-- Database "template1" dump
--

\connect template1

--
-- PostgreSQL database dump
--

\restrict DfYGqjGYXueWEfHAukXtNRefynQzC9hIzQgCFmerRF42bBC84wssu1qXL0wmUqm

-- Dumped from database version 16.10 (Ubuntu 16.10-0ubuntu0.24.04.1)
-- Dumped by pg_dump version 16.10 (Ubuntu 16.10-0ubuntu0.24.04.1)

SET statement_timeout = 0;
SET lock_timeout = 0;
SET idle_in_transaction_session_timeout = 0;
SET client_encoding = 'UTF8';
SET standard_conforming_strings = on;
SELECT pg_catalog.set_config('search_path', '', false);
SET check_function_bodies = false;
SET xmloption = content;
SET client_min_messages = warning;
SET row_security = off;

--
-- PostgreSQL database dump complete
--

\unrestrict DfYGqjGYXueWEfHAukXtNRefynQzC9hIzQgCFmerRF42bBC84wssu1qXL0wmUqm

--
-- Database "SDNfw" dump
--

--
-- PostgreSQL database dump
--

\restrict qe2hhrDfspsnJa1td1gKjjhbwLjd7zJ0SRn8aRE5IDV4qsQIGVrvaiuheWewbYY

-- Dumped from database version 16.10 (Ubuntu 16.10-0ubuntu0.24.04.1)
-- Dumped by pg_dump version 16.10 (Ubuntu 16.10-0ubuntu0.24.04.1)

SET statement_timeout = 0;
SET lock_timeout = 0;
SET idle_in_transaction_session_timeout = 0;
SET client_encoding = 'UTF8';
SET standard_conforming_strings = on;
SELECT pg_catalog.set_config('search_path', '', false);
SET check_function_bodies = false;
SET xmloption = content;
SET client_min_messages = warning;
SET row_security = off;

--
-- Name: SDNfw; Type: DATABASE; Schema: -; Owner: srv_acc
--

CREATE DATABASE "SDNfw" WITH TEMPLATE = template0 ENCODING = 'UTF8' LOCALE_PROVIDER = libc LOCALE = 'en_US.UTF-8';


ALTER DATABASE "SDNfw" OWNER TO srv_acc;

\unrestrict qe2hhrDfspsnJa1td1gKjjhbwLjd7zJ0SRn8aRE5IDV4qsQIGVrvaiuheWewbYY
\connect "SDNfw"
\restrict qe2hhrDfspsnJa1td1gKjjhbwLjd7zJ0SRn8aRE5IDV4qsQIGVrvaiuheWewbYY

SET statement_timeout = 0;
SET lock_timeout = 0;
SET idle_in_transaction_session_timeout = 0;
SET client_encoding = 'UTF8';
SET standard_conforming_strings = on;
SELECT pg_catalog.set_config('search_path', '', false);
SET check_function_bodies = false;
SET xmloption = content;
SET client_min_messages = warning;
SET row_security = off;

SET default_tablespace = '';

SET default_table_access_method = heap;

--
-- Name: policy; Type: TABLE; Schema: public; Owner: srv_acc
--

CREATE TABLE public.policy (
    id integer NOT NULL,
    name text NOT NULL,
    srcip inet[] NOT NULL,
    srcuser text[] NOT NULL,
    dstip inet[] NOT NULL,
    tcp_ports integer[],
    udp_ports integer[],
    icmp boolean DEFAULT false,
    action boolean NOT NULL,
    disabled boolean DEFAULT false,
    schedule date
);


ALTER TABLE public.policy OWNER TO srv_acc;

--
-- Name: policy_id_seq; Type: SEQUENCE; Schema: public; Owner: srv_acc
--

CREATE SEQUENCE public.policy_id_seq
    AS integer
    START WITH 1
    INCREMENT BY 1
    NO MINVALUE
    NO MAXVALUE
    CACHE 1;


ALTER SEQUENCE public.policy_id_seq OWNER TO srv_acc;

--
-- Name: policy_id_seq; Type: SEQUENCE OWNED BY; Schema: public; Owner: srv_acc
--

ALTER SEQUENCE public.policy_id_seq OWNED BY public.policy.id;


--
-- Name: policy id; Type: DEFAULT; Schema: public; Owner: srv_acc
--

ALTER TABLE ONLY public.policy ALTER COLUMN id SET DEFAULT nextval('public.policy_id_seq'::regclass);


--
-- Data for Name: policy; Type: TABLE DATA; Schema: public; Owner: srv_acc
--

COPY public.policy (id, name, srcip, srcuser, dstip, tcp_ports, udp_ports, icmp, action, disabled, schedule) FROM stdin;
1	All_to_DNS	{}	{}	{10.10.10.10}	\N	{53}	t	t	f	\N
2	AD_to_Ctrl	{10.10.0.10}	{}	{10.10.10.10}	{8000}	\N	f	t	f	\N
3	Usr_to_Cloudfare	{}	{johndoe}	{1.1.1.1}	{80}	\N	t	t	f	\N
4	Usr_to_DNSggl	{}	{"Domain Users"}	{8.8.8.8,8.8.4.4}	\N	\N	t	t	f	\N
5	Inbound ICMP	{}	{}	{192.168.230.155}	\N	\N	t	t	f	\N
\.


--
-- Name: policy_id_seq; Type: SEQUENCE SET; Schema: public; Owner: srv_acc
--

SELECT pg_catalog.setval('public.policy_id_seq', 5, true);


--
-- Name: policy policy_pkey; Type: CONSTRAINT; Schema: public; Owner: srv_acc
--

ALTER TABLE ONLY public.policy
    ADD CONSTRAINT policy_pkey PRIMARY KEY (id);


--
-- PostgreSQL database dump complete
--

\unrestrict qe2hhrDfspsnJa1td1gKjjhbwLjd7zJ0SRn8aRE5IDV4qsQIGVrvaiuheWewbYY

--
-- Database "postgres" dump
--

\connect postgres

--
-- PostgreSQL database dump
--

\restrict zAxalUwFx7FJZ2UxurGSxTW3FoOGxgt0vs1Gg9vM30IY9NmpdYyAIxms9tXepla

-- Dumped from database version 16.10 (Ubuntu 16.10-0ubuntu0.24.04.1)
-- Dumped by pg_dump version 16.10 (Ubuntu 16.10-0ubuntu0.24.04.1)

SET statement_timeout = 0;
SET lock_timeout = 0;
SET idle_in_transaction_session_timeout = 0;
SET client_encoding = 'UTF8';
SET standard_conforming_strings = on;
SELECT pg_catalog.set_config('search_path', '', false);
SET check_function_bodies = false;
SET xmloption = content;
SET client_min_messages = warning;
SET row_security = off;

--
-- PostgreSQL database dump complete
--

\unrestrict zAxalUwFx7FJZ2UxurGSxTW3FoOGxgt0vs1Gg9vM30IY9NmpdYyAIxms9tXepla

--
-- PostgreSQL database cluster dump complete
--

