--
-- PostgreSQL database cluster dump
--

\restrict yadlyHyXgk19bJECIuaq7mDwuJ5yjnc0h0ysygxork6OHxyEFiotIyvvMsV514z

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








\unrestrict yadlyHyXgk19bJECIuaq7mDwuJ5yjnc0h0ysygxork6OHxyEFiotIyvvMsV514z

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

\restrict piPE4Xl5nBcRslRpXigYQZ5Zg10PUkZIMRc7ps17rWKiqKFIsQq32ajX0yRGPnb

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

\unrestrict piPE4Xl5nBcRslRpXigYQZ5Zg10PUkZIMRc7ps17rWKiqKFIsQq32ajX0yRGPnb

--
-- Database "SDNfw" dump
--

--
-- PostgreSQL database dump
--

\restrict i3HQFiUE3jqpZYIYY40GqvWd221ygGJrIjGS9mzLeeAvv9b5ri8JPkmUjGMTOhF

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

\unrestrict i3HQFiUE3jqpZYIYY40GqvWd221ygGJrIjGS9mzLeeAvv9b5ri8JPkmUjGMTOhF
\connect "SDNfw"
\restrict i3HQFiUE3jqpZYIYY40GqvWd221ygGJrIjGS9mzLeeAvv9b5ri8JPkmUjGMTOhF

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
-- Name: policy_reorder(); Type: FUNCTION; Schema: public; Owner: srv_acc
--

CREATE FUNCTION public.policy_reorder() RETURNS trigger
    LANGUAGE plpgsql
    AS $$
BEGIN
  -- Reassign order_index starting from 1
  WITH reordered AS (
    SELECT id, ROW_NUMBER() OVER (ORDER BY order_index) AS new_order
    FROM policy
  )
  UPDATE policy p
  SET order_index = r.new_order
  FROM reordered r
  WHERE p.id = r.id;

  RETURN NULL;
END;
$$;


ALTER FUNCTION public.policy_reorder() OWNER TO srv_acc;

--
-- Name: policy_set_order(); Type: FUNCTION; Schema: public; Owner: srv_acc
--

CREATE FUNCTION public.policy_set_order() RETURNS trigger
    LANGUAGE plpgsql
    AS $$
BEGIN
  -- If no order_index specified, append at bottom
  IF NEW.order_index IS NULL THEN
    SELECT COALESCE(MAX(order_index), 0) + 1 INTO NEW.order_index FROM policy;
    RETURN NEW;
  END IF;

  -- If order_index is specified, shift down existing rules
  UPDATE policy
  SET order_index = order_index + 1
  WHERE order_index >= NEW.order_index;

  RETURN NEW;
END;
$$;


ALTER FUNCTION public.policy_set_order() OWNER TO srv_acc;

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
    schedule date,
    order_index integer
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
-- Name: users; Type: TABLE; Schema: public; Owner: srv_acc
--

CREATE TABLE public.users (
    id integer NOT NULL,
    username text NOT NULL,
    password_hash text NOT NULL,
    user_mgmt boolean DEFAULT false,
    policy_mgmt boolean DEFAULT false,
    user_view boolean DEFAULT false,
    policy_view boolean DEFAULT false
);


ALTER TABLE public.users OWNER TO srv_acc;

--
-- Name: users_id_seq; Type: SEQUENCE; Schema: public; Owner: srv_acc
--

CREATE SEQUENCE public.users_id_seq
    AS integer
    START WITH 1
    INCREMENT BY 1
    NO MINVALUE
    NO MAXVALUE
    CACHE 1;


ALTER SEQUENCE public.users_id_seq OWNER TO srv_acc;

--
-- Name: users_id_seq; Type: SEQUENCE OWNED BY; Schema: public; Owner: srv_acc
--

ALTER SEQUENCE public.users_id_seq OWNED BY public.users.id;


--
-- Name: policy id; Type: DEFAULT; Schema: public; Owner: srv_acc
--

ALTER TABLE ONLY public.policy ALTER COLUMN id SET DEFAULT nextval('public.policy_id_seq'::regclass);


--
-- Name: users id; Type: DEFAULT; Schema: public; Owner: srv_acc
--

ALTER TABLE ONLY public.users ALTER COLUMN id SET DEFAULT nextval('public.users_id_seq'::regclass);


--
-- Data for Name: policy; Type: TABLE DATA; Schema: public; Owner: srv_acc
--

COPY public.policy (id, name, srcip, srcuser, dstip, tcp_ports, udp_ports, icmp, action, disabled, schedule, order_index) FROM stdin;
1	All_to_DNS	{}	{}	{10.10.10.10}	\N	{53}	t	t	f	\N	1
3	Usr_to_Cloudfare	{}	{johndoe}	{1.1.1.1}	{80}	\N	t	t	f	\N	3
4	Usr_to_DNSggl	{}	{"Domain Users"}	{8.8.8.8,8.8.4.4}	\N	\N	t	t	f	\N	4
5	Inbound ICMP	{}	{}	{192.168.230.155}	\N	\N	t	t	f	\N	5
2	AD_to_Ctrl	{10.10.0.10}	{}	{10.10.10.10}	{8000,21012}	\N	f	t	f	\N	2
\.


--
-- Data for Name: users; Type: TABLE DATA; Schema: public; Owner: srv_acc
--

COPY public.users (id, username, password_hash, user_mgmt, policy_mgmt, user_view, policy_view) FROM stdin;
1	admin	scrypt:32768:8:1$gokpvJw2pRBgTxc8$9927d29b5bfa1a4010ac57930d6275b8dcae37d56d95cac06dbf7f86a1a6258e67c8502fc3ddfb88431cf5984c858bab1c5baff276e1ccd31bd12f2fc8cfb91b	t	t	t	t
\.


--
-- Name: policy_id_seq; Type: SEQUENCE SET; Schema: public; Owner: srv_acc
--

SELECT pg_catalog.setval('public.policy_id_seq', 6, true);


--
-- Name: users_id_seq; Type: SEQUENCE SET; Schema: public; Owner: srv_acc
--

SELECT pg_catalog.setval('public.users_id_seq', 1, true);


--
-- Name: policy policy_pkey; Type: CONSTRAINT; Schema: public; Owner: srv_acc
--

ALTER TABLE ONLY public.policy
    ADD CONSTRAINT policy_pkey PRIMARY KEY (id);


--
-- Name: users users_pkey; Type: CONSTRAINT; Schema: public; Owner: srv_acc
--

ALTER TABLE ONLY public.users
    ADD CONSTRAINT users_pkey PRIMARY KEY (id);


--
-- Name: users users_username_key; Type: CONSTRAINT; Schema: public; Owner: srv_acc
--

ALTER TABLE ONLY public.users
    ADD CONSTRAINT users_username_key UNIQUE (username);


--
-- Name: policy trg_policy_reorder; Type: TRIGGER; Schema: public; Owner: srv_acc
--

CREATE TRIGGER trg_policy_reorder AFTER DELETE ON public.policy FOR EACH ROW EXECUTE FUNCTION public.policy_reorder();


--
-- Name: policy trg_policy_set_order; Type: TRIGGER; Schema: public; Owner: srv_acc
--

CREATE TRIGGER trg_policy_set_order BEFORE INSERT ON public.policy FOR EACH ROW EXECUTE FUNCTION public.policy_set_order();


--
-- PostgreSQL database dump complete
--

\unrestrict i3HQFiUE3jqpZYIYY40GqvWd221ygGJrIjGS9mzLeeAvv9b5ri8JPkmUjGMTOhF

--
-- Database "postgres" dump
--

\connect postgres

--
-- PostgreSQL database dump
--

\restrict jW93rEfQehOR02S18UFTH6HW1UNI2lqB6m474P2j9K45FCqSaAOPegRYpHOPEXb

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

\unrestrict jW93rEfQehOR02S18UFTH6HW1UNI2lqB6m474P2j9K45FCqSaAOPegRYpHOPEXb

--
-- PostgreSQL database cluster dump complete
--

