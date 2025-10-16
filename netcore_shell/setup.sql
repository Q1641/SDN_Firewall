--
-- PostgreSQL database cluster dump
--

\restrict ZwkuvuTxUF7XfoDZUfB7akRYZy7gVu2Gd6c8EXHbUcLrRZgxKDLPRCpuif52D74

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








\unrestrict ZwkuvuTxUF7XfoDZUfB7akRYZy7gVu2Gd6c8EXHbUcLrRZgxKDLPRCpuif52D74

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

\restrict ScxuAh4cAkyDGdSD1Z8sAd8ZpqK1t0qcOeL3P4nY2bzVLDnHO7xWe6MmyLo0vMH

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

\unrestrict ScxuAh4cAkyDGdSD1Z8sAd8ZpqK1t0qcOeL3P4nY2bzVLDnHO7xWe6MmyLo0vMH

--
-- Database "SDNfw" dump
--

--
-- PostgreSQL database dump
--

\restrict gyHjRanzgBKcHLYbyg9hUMOFucVnnEM5gSFdJPfTrhAXxsl24RyGiT1rwxtnqKS

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

\unrestrict gyHjRanzgBKcHLYbyg9hUMOFucVnnEM5gSFdJPfTrhAXxsl24RyGiT1rwxtnqKS
\connect "SDNfw"
\restrict gyHjRanzgBKcHLYbyg9hUMOFucVnnEM5gSFdJPfTrhAXxsl24RyGiT1rwxtnqKS

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
-- Name: logs; Type: TABLE; Schema: public; Owner: srv_acc
--

CREATE TABLE public.logs (
    id integer NOT NULL,
    srcip inet NOT NULL,
    srcuser text,
    dstip inet NOT NULL,
    rulename text,
    ruleid integer,
    action boolean,
    dpid bigint,
    "timestamp" timestamp with time zone DEFAULT now(),
    tcpport integer,
    udpport integer,
    icmp boolean
);


ALTER TABLE public.logs OWNER TO srv_acc;

--
-- Name: logs_id_seq; Type: SEQUENCE; Schema: public; Owner: srv_acc
--

CREATE SEQUENCE public.logs_id_seq
    AS integer
    START WITH 1
    INCREMENT BY 1
    NO MINVALUE
    NO MAXVALUE
    CACHE 1;


ALTER SEQUENCE public.logs_id_seq OWNER TO srv_acc;

--
-- Name: logs_id_seq; Type: SEQUENCE OWNED BY; Schema: public; Owner: srv_acc
--

ALTER SEQUENCE public.logs_id_seq OWNED BY public.logs.id;


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
    order_index integer,
    domains text[]
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
-- Name: logs id; Type: DEFAULT; Schema: public; Owner: srv_acc
--

ALTER TABLE ONLY public.logs ALTER COLUMN id SET DEFAULT nextval('public.logs_id_seq'::regclass);


--
-- Name: policy id; Type: DEFAULT; Schema: public; Owner: srv_acc
--

ALTER TABLE ONLY public.policy ALTER COLUMN id SET DEFAULT nextval('public.policy_id_seq'::regclass);


--
-- Name: users id; Type: DEFAULT; Schema: public; Owner: srv_acc
--

ALTER TABLE ONLY public.users ALTER COLUMN id SET DEFAULT nextval('public.users_id_seq'::regclass);


--
-- Data for Name: logs; Type: TABLE DATA; Schema: public; Owner: srv_acc
--

COPY public.logs (id, srcip, srcuser, dstip, rulename, ruleid, action, dpid, "timestamp", tcpport, udpport, icmp) FROM stdin;
1284	10.10.0.11	\N	74.178.240.61	user_to_fwmgmt	\N	f	2	2025-10-16 23:02:31.740788+07	443	\N	f
1285	10.10.0.10	\N	135.232.92.137	user_to_fwmgmt	\N	f	2	2025-10-16 23:02:36.160676+07	443	\N	f
1286	10.10.0.11	\N	10.10.0.10	user_to_fwmgmt	\N	f	2	2025-10-16 23:02:38.801361+07	445	\N	f
1287	10.10.0.10	\N	10.10.0.11	user_to_fwmgmt	\N	f	2	2025-10-16 23:02:38.818546+07	55809	\N	f
1288	10.10.0.11	\N	10.10.0.10	user_to_fwmgmt	\N	f	2	2025-10-16 23:02:38.840426+07	445	\N	f
1289	10.10.0.11	\N	10.10.0.10	user_to_fwmgmt	\N	f	2	2025-10-16 23:02:38.86153+07	445	\N	f
1290	10.10.0.10	\N	10.10.0.11	user_to_fwmgmt	\N	f	2	2025-10-16 23:02:38.880442+07	55809	\N	f
1291	10.10.0.11	\N	10.10.0.10	user_to_fwmgmt	\N	f	2	2025-10-16 23:02:38.898675+07	445	\N	f
1292	10.10.0.10	\N	10.10.0.11	user_to_fwmgmt	\N	f	2	2025-10-16 23:02:38.919254+07	55809	\N	f
1293	10.10.0.11	\N	10.10.0.10	user_to_fwmgmt	\N	f	2	2025-10-16 23:02:38.956347+07	445	\N	f
1294	10.10.0.11	\N	10.10.0.10	user_to_fwmgmt	\N	f	2	2025-10-16 23:02:38.977703+07	445	\N	f
1295	10.10.0.11	\N	10.10.0.10	user_to_fwmgmt	\N	f	2	2025-10-16 23:02:38.997031+07	445	\N	f
1296	10.10.0.10	\N	10.10.0.11	user_to_fwmgmt	\N	f	2	2025-10-16 23:02:39.012218+07	55809	\N	f
1297	10.10.0.10	\N	10.10.0.11	user_to_fwmgmt	\N	f	2	2025-10-16 23:02:39.047615+07	55809	\N	f
1298	10.10.0.11	\N	10.10.0.10	user_to_fwmgmt	\N	f	2	2025-10-16 23:02:39.0757+07	445	\N	f
1299	10.10.0.10	\N	10.10.0.11	user_to_fwmgmt	\N	f	2	2025-10-16 23:02:39.103572+07	55809	\N	f
1300	10.10.0.11	\N	10.10.0.10	user_to_fwmgmt	\N	f	2	2025-10-16 23:02:39.130517+07	445	\N	f
1301	10.10.0.11	\N	10.10.0.10	user_to_fwmgmt	\N	f	2	2025-10-16 23:02:39.160961+07	445	\N	f
1302	10.10.0.10	\N	10.10.0.11	user_to_fwmgmt	\N	f	2	2025-10-16 23:02:39.187211+07	55809	\N	f
1303	10.10.0.10	\N	10.10.0.11	user_to_fwmgmt	\N	f	2	2025-10-16 23:02:39.350999+07	55809	\N	f
1304	10.10.0.10	\N	10.10.0.11	user_to_fwmgmt	\N	f	2	2025-10-16 23:02:39.376086+07	55809	\N	f
1305	10.10.0.11	\N	10.10.0.10	user_to_fwmgmt	\N	f	2	2025-10-16 23:02:39.400771+07	445	\N	f
1306	10.10.0.11	\N	239.255.255.250	user_to_fwmgmt	\N	f	2	2025-10-16 23:02:44.254818+07	\N	1900	f
1307	10.10.0.10	\N	1.1.1.1	user_to_fwmgmt	\N	f	2	2025-10-16 23:02:44.872482+07	\N	53	f
1308	10.10.0.11	\N	74.178.240.61	user_to_fwmgmt	\N	f	2	2025-10-16 23:02:45.790498+07	443	\N	f
1309	10.10.0.10	\N	10.10.10.10	All_to_DNS	1	t	2	2025-10-16 23:02:46.880549+07	\N	53	f
1310	10.10.0.10	\N	10.10.10.10	All_to_DNS	1	t	2	2025-10-16 23:02:48.876596+07	\N	53	f
1311	10.10.0.10	\N	1.1.1.1	user_to_fwmgmt	\N	f	2	2025-10-16 23:02:48.89503+07	\N	53	f
1312	10.10.0.1	\N	224.0.0.22	user_to_fwmgmt	\N	f	2	2025-10-16 23:02:51.754556+07	\N	\N	f
1313	192.168.230.1	\N	224.0.0.22	user_to_fwmgmt	\N	f	1	2025-10-16 23:02:51.774859+07	\N	\N	f
1314	192.168.230.1	\N	224.0.0.22	user_to_fwmgmt	\N	f	1	2025-10-16 23:02:51.804195+07	\N	\N	f
1315	192.168.230.1	\N	224.0.0.252	user_to_fwmgmt	\N	f	1	2025-10-16 23:02:51.823508+07	\N	5355	f
1316	10.20.0.1	\N	224.0.0.22	user_to_fwmgmt	\N	f	3	2025-10-16 23:02:51.844248+07	\N	\N	f
1317	10.20.0.1	\N	224.0.0.22	user_to_fwmgmt	\N	f	3	2025-10-16 23:02:51.86616+07	\N	\N	f
1318	10.20.0.1	\N	224.0.0.252	user_to_fwmgmt	\N	f	3	2025-10-16 23:02:51.892417+07	\N	5355	f
1319	10.10.0.1	\N	224.0.0.22	user_to_fwmgmt	\N	f	2	2025-10-16 23:02:51.913231+07	\N	\N	f
1320	10.10.0.1	\N	224.0.0.252	user_to_fwmgmt	\N	f	2	2025-10-16 23:02:51.930508+07	\N	5355	f
1321	10.10.0.1	\N	224.0.0.252	user_to_fwmgmt	\N	f	2	2025-10-16 23:02:52.634903+07	\N	5355	f
1322	192.168.230.1	\N	224.0.0.252	user_to_fwmgmt	\N	f	1	2025-10-16 23:02:52.654295+07	\N	5355	f
1323	10.20.0.1	\N	224.0.0.252	user_to_fwmgmt	\N	f	3	2025-10-16 23:02:52.671967+07	\N	5355	f
1324	10.10.0.10	\N	20.210.166.59	user_to_fwmgmt	\N	f	2	2025-10-16 23:02:52.954734+07	443	\N	f
1325	10.10.0.10	\N	1.1.1.1	user_to_fwmgmt	\N	f	2	2025-10-16 23:02:57.178983+07	\N	53	f
1326	10.10.0.10	\N	74.178.240.61	user_to_fwmgmt	\N	f	2	2025-10-16 23:02:58.205314+07	443	\N	f
1327	10.10.0.11	\N	10.10.10.10	All_to_DNS	1	t	2	2025-10-16 23:03:02.148751+07	\N	53	f
1328	10.10.0.11	\N	10.10.0.10	user_to_fwmgmt	\N	f	2	2025-10-16 23:03:02.293019+07	\N	53	f
1329	10.10.0.10	\N	1.1.1.1	user_to_fwmgmt	\N	f	2	2025-10-16 23:03:02.327068+07	\N	53	f
1330	10.10.0.11	\N	52.183.220.149	user_to_fwmgmt	\N	f	2	2025-10-16 23:03:03.360964+07	443	\N	f
1331	10.10.0.11	\N	10.10.0.10	user_to_fwmgmt	\N	f	2	2025-10-16 23:03:06.121028+07	445	\N	f
1332	10.10.0.10	\N	10.10.0.11	user_to_fwmgmt	\N	f	2	2025-10-16 23:03:06.145442+07	55812	\N	f
1333	10.10.0.11	\N	10.10.0.10	user_to_fwmgmt	\N	f	2	2025-10-16 23:03:06.175804+07	445	\N	f
1334	10.10.0.11	\N	10.10.0.10	user_to_fwmgmt	\N	f	2	2025-10-16 23:03:06.202127+07	445	\N	f
1335	10.10.0.10	\N	10.10.0.11	user_to_fwmgmt	\N	f	2	2025-10-16 23:03:06.24417+07	55812	\N	f
1336	10.10.0.11	\N	10.10.0.10	user_to_fwmgmt	\N	f	2	2025-10-16 23:03:06.285794+07	445	\N	f
1337	10.10.0.10	\N	10.10.0.11	user_to_fwmgmt	\N	f	2	2025-10-16 23:03:06.32629+07	55812	\N	f
1338	10.10.0.11	\N	10.10.0.10	user_to_fwmgmt	\N	f	2	2025-10-16 23:03:06.373738+07	88	\N	f
1339	10.10.0.11	\N	10.10.0.10	user_to_fwmgmt	\N	f	2	2025-10-16 23:03:06.410217+07	88	\N	f
1340	10.10.0.10	\N	10.10.0.11	user_to_fwmgmt	\N	f	2	2025-10-16 23:03:06.437812+07	55813	\N	f
1341	10.10.0.11	\N	10.10.0.10	user_to_fwmgmt	\N	f	2	2025-10-16 23:03:06.46683+07	88	\N	f
1342	10.10.0.11	\N	10.10.0.10	user_to_fwmgmt	\N	f	2	2025-10-16 23:03:06.48976+07	88	\N	f
1343	10.10.0.10	\N	10.10.0.11	user_to_fwmgmt	\N	f	2	2025-10-16 23:03:06.504914+07	55813	\N	f
1344	10.10.0.10	\N	10.10.0.11	user_to_fwmgmt	\N	f	2	2025-10-16 23:03:06.526159+07	55813	\N	f
1345	10.10.0.10	\N	10.10.0.11	user_to_fwmgmt	\N	f	2	2025-10-16 23:03:06.546849+07	55813	\N	f
1346	10.10.0.10	\N	10.10.0.11	user_to_fwmgmt	\N	f	2	2025-10-16 23:03:06.565658+07	55812	\N	f
1347	10.10.0.11	\N	10.10.0.10	user_to_fwmgmt	\N	f	2	2025-10-16 23:03:06.583158+07	445	\N	f
1348	10.10.0.11	\N	10.10.0.10	user_to_fwmgmt	\N	f	2	2025-10-16 23:03:06.602801+07	88	\N	f
1349	10.10.0.11	\N	10.10.0.10	user_to_fwmgmt	\N	f	2	2025-10-16 23:03:06.621615+07	88	\N	f
1350	10.10.0.10	\N	10.10.0.11	user_to_fwmgmt	\N	f	2	2025-10-16 23:03:06.646638+07	55813	\N	f
1351	10.10.0.10	\N	10.10.0.11	user_to_fwmgmt	\N	f	2	2025-10-16 23:03:06.674105+07	55813	\N	f
1352	10.10.0.11	\N	10.10.0.10	user_to_fwmgmt	\N	f	2	2025-10-16 23:03:06.723153+07	88	\N	f
1353	10.10.0.10	\N	10.10.0.11	user_to_fwmgmt	\N	f	2	2025-10-16 23:03:06.764899+07	55814	\N	f
1354	10.10.0.11	\N	10.10.0.10	user_to_fwmgmt	\N	f	2	2025-10-16 23:03:06.799484+07	88	\N	f
1355	10.10.0.11	\N	10.10.0.10	user_to_fwmgmt	\N	f	2	2025-10-16 23:03:06.844104+07	88	\N	f
1356	10.10.0.11	\N	10.10.0.10	user_to_fwmgmt	\N	f	2	2025-10-16 23:03:06.892817+07	88	\N	f
1357	10.10.0.10	\N	10.10.0.11	user_to_fwmgmt	\N	f	2	2025-10-16 23:03:06.919988+07	55814	\N	f
1358	10.10.0.10	\N	10.10.0.11	user_to_fwmgmt	\N	f	2	2025-10-16 23:03:06.949617+07	55814	\N	f
1359	10.10.0.10	\N	10.10.0.11	user_to_fwmgmt	\N	f	2	2025-10-16 23:03:06.975601+07	55814	\N	f
1360	10.10.0.11	\N	10.10.0.10	user_to_fwmgmt	\N	f	2	2025-10-16 23:03:06.996725+07	88	\N	f
1361	10.10.0.11	\N	10.10.0.10	user_to_fwmgmt	\N	f	2	2025-10-16 23:03:07.014617+07	88	\N	f
1362	10.10.0.10	\N	10.10.0.11	user_to_fwmgmt	\N	f	2	2025-10-16 23:03:07.035288+07	55814	\N	f
1363	10.10.0.10	\N	10.10.0.11	user_to_fwmgmt	\N	f	2	2025-10-16 23:03:07.056232+07	55814	\N	f
1364	10.10.0.11	\N	10.10.0.10	user_to_fwmgmt	\N	f	2	2025-10-16 23:03:07.082157+07	445	\N	f
1365	10.10.0.11	\N	10.10.0.10	user_to_fwmgmt	\N	f	2	2025-10-16 23:03:07.110969+07	445	\N	f
1366	10.10.0.11	\N	10.10.0.10	user_to_fwmgmt	\N	f	2	2025-10-16 23:03:07.13288+07	445	\N	f
1367	10.10.0.10	\N	10.10.0.11	user_to_fwmgmt	\N	f	2	2025-10-16 23:03:07.157875+07	55812	\N	f
1368	10.10.0.10	\N	10.10.0.11	user_to_fwmgmt	\N	f	2	2025-10-16 23:03:07.187385+07	55812	\N	f
1369	10.10.0.11	\N	10.10.0.10	user_to_fwmgmt	\N	f	2	2025-10-16 23:03:07.208259+07	445	\N	f
1370	10.10.0.10	\N	10.10.0.11	user_to_fwmgmt	\N	f	2	2025-10-16 23:03:07.229723+07	55812	\N	f
1371	10.10.0.11	\N	10.10.0.10	user_to_fwmgmt	\N	f	2	2025-10-16 23:03:07.260076+07	445	\N	f
1372	10.10.0.10	\N	10.10.0.11	user_to_fwmgmt	\N	f	2	2025-10-16 23:03:07.287721+07	55812	\N	f
1373	10.10.0.10	\N	10.10.0.11	user_to_fwmgmt	\N	f	2	2025-10-16 23:03:07.310339+07	55812	\N	f
1374	10.10.0.10	\N	10.10.0.11	user_to_fwmgmt	\N	f	2	2025-10-16 23:03:07.333452+07	55812	\N	f
1375	10.10.0.10	\N	10.10.0.11	user_to_fwmgmt	\N	f	2	2025-10-16 23:03:07.354132+07	55812	\N	f
1376	10.10.0.10	\N	10.10.0.11	user_to_fwmgmt	\N	f	2	2025-10-16 23:03:07.376714+07	55812	\N	f
1377	10.10.0.10	\N	10.10.0.11	user_to_fwmgmt	\N	f	2	2025-10-16 23:03:07.403108+07	55812	\N	f
1378	10.10.0.10	\N	10.10.0.11	user_to_fwmgmt	\N	f	2	2025-10-16 23:03:07.428656+07	55812	\N	f
1379	10.10.0.10	\N	10.10.0.11	user_to_fwmgmt	\N	f	2	2025-10-16 23:03:07.456463+07	55812	\N	f
1380	10.10.0.10	\N	10.10.0.11	user_to_fwmgmt	\N	f	2	2025-10-16 23:03:07.48523+07	55812	\N	f
1381	10.10.0.10	\N	10.10.0.11	user_to_fwmgmt	\N	f	2	2025-10-16 23:03:07.509153+07	55812	\N	f
1382	10.10.0.10	\N	10.10.0.11	user_to_fwmgmt	\N	f	2	2025-10-16 23:03:07.533128+07	55812	\N	f
1383	10.10.0.10	\N	10.10.0.11	user_to_fwmgmt	\N	f	2	2025-10-16 23:03:07.554555+07	55812	\N	f
1384	10.10.0.10	\N	10.10.0.11	user_to_fwmgmt	\N	f	2	2025-10-16 23:03:07.577701+07	55812	\N	f
1385	10.10.0.10	\N	10.10.0.11	user_to_fwmgmt	\N	f	2	2025-10-16 23:03:07.601625+07	55812	\N	f
1386	10.10.0.10	\N	10.10.0.11	user_to_fwmgmt	\N	f	2	2025-10-16 23:03:07.626077+07	55812	\N	f
1387	10.10.0.10	\N	10.10.0.11	user_to_fwmgmt	\N	f	2	2025-10-16 23:03:07.646953+07	55812	\N	f
1388	10.10.0.10	\N	10.10.0.11	user_to_fwmgmt	\N	f	2	2025-10-16 23:03:07.672414+07	55812	\N	f
1389	10.10.0.10	\N	10.10.0.11	user_to_fwmgmt	\N	f	2	2025-10-16 23:03:07.697998+07	55812	\N	f
1390	10.10.0.11	\N	74.178.240.61	user_to_fwmgmt	\N	f	2	2025-10-16 23:03:07.725154+07	443	\N	f
1391	10.10.0.10	\N	10.10.10.10	AD_to_Ctrl	2	t	2	2025-10-16 23:03:08.489393+07	21012	\N	f
1392	10.10.0.10	\N	10.10.0.11	user_to_fwmgmt	\N	f	2	2025-10-16 23:03:11.459779+07	\N	49764	f
1393	10.10.0.10	\N	74.178.240.61	user_to_fwmgmt	\N	f	2	2025-10-16 23:03:19.268216+07	443	\N	f
1394	10.10.0.11	johndoe	10.10.0.10	user_to_fwmgmt	\N	f	2	2025-10-16 23:03:21.825532+07	88	\N	f
1395	10.10.0.10	\N	10.10.0.11	user_to_fwmgmt	\N	f	2	2025-10-16 23:03:21.850919+07	55816	\N	f
1396	10.10.0.11	johndoe	10.10.0.10	user_to_fwmgmt	\N	f	2	2025-10-16 23:03:21.87206+07	88	\N	f
1397	10.10.0.11	johndoe	10.10.0.10	user_to_fwmgmt	\N	f	2	2025-10-16 23:03:21.891106+07	88	\N	f
1398	10.10.0.10	\N	10.10.0.11	user_to_fwmgmt	\N	f	2	2025-10-16 23:03:21.909359+07	55816	\N	f
1399	10.10.0.11	johndoe	10.10.0.10	user_to_fwmgmt	\N	f	2	2025-10-16 23:03:21.933452+07	88	\N	f
1400	10.10.0.10	\N	10.10.0.11	user_to_fwmgmt	\N	f	2	2025-10-16 23:03:21.957024+07	55816	\N	f
1401	10.10.0.10	\N	10.10.0.11	user_to_fwmgmt	\N	f	2	2025-10-16 23:03:21.978321+07	55816	\N	f
1402	10.10.0.11	johndoe	10.10.0.10	user_to_fwmgmt	\N	f	2	2025-10-16 23:03:22.001626+07	88	\N	f
1403	10.10.0.10	\N	10.10.0.11	user_to_fwmgmt	\N	f	2	2025-10-16 23:03:22.023084+07	55817	\N	f
1404	10.10.0.11	johndoe	10.10.0.10	user_to_fwmgmt	\N	f	2	2025-10-16 23:03:22.04396+07	88	\N	f
1405	10.10.0.11	johndoe	10.10.0.10	user_to_fwmgmt	\N	f	2	2025-10-16 23:03:22.064823+07	88	\N	f
1406	10.10.0.10	\N	10.10.0.11	user_to_fwmgmt	\N	f	2	2025-10-16 23:03:22.084695+07	55817	\N	f
1407	10.10.0.10	\N	10.10.0.11	user_to_fwmgmt	\N	f	2	2025-10-16 23:03:22.10363+07	55817	\N	f
1408	10.10.0.11	johndoe	10.10.0.10	user_to_fwmgmt	\N	f	2	2025-10-16 23:03:22.122563+07	88	\N	f
1409	10.10.0.11	johndoe	10.10.0.10	user_to_fwmgmt	\N	f	2	2025-10-16 23:03:22.14184+07	88	\N	f
1410	10.10.0.10	\N	10.10.0.11	user_to_fwmgmt	\N	f	2	2025-10-16 23:03:22.160994+07	55817	\N	f
1411	10.10.0.10	\N	10.10.0.11	user_to_fwmgmt	\N	f	2	2025-10-16 23:03:22.183468+07	55817	\N	f
1412	10.10.0.11	johndoe	10.10.0.10	user_to_fwmgmt	\N	f	2	2025-10-16 23:03:22.204563+07	88	\N	f
1413	10.10.0.10	\N	10.10.0.11	user_to_fwmgmt	\N	f	2	2025-10-16 23:03:22.224578+07	55818	\N	f
1414	10.10.0.11	johndoe	10.10.0.10	user_to_fwmgmt	\N	f	2	2025-10-16 23:03:22.242873+07	88	\N	f
1415	10.10.0.11	johndoe	10.10.0.10	user_to_fwmgmt	\N	f	2	2025-10-16 23:03:22.262757+07	88	\N	f
1416	10.10.0.11	johndoe	10.10.0.10	user_to_fwmgmt	\N	f	2	2025-10-16 23:03:22.280371+07	88	\N	f
1417	10.10.0.10	\N	10.10.0.11	user_to_fwmgmt	\N	f	2	2025-10-16 23:03:22.304542+07	55818	\N	f
1418	10.10.0.10	\N	10.10.0.11	user_to_fwmgmt	\N	f	2	2025-10-16 23:03:22.32696+07	55818	\N	f
1419	10.10.0.10	\N	10.10.0.11	user_to_fwmgmt	\N	f	2	2025-10-16 23:03:22.353157+07	55818	\N	f
1420	10.10.0.11	johndoe	10.10.0.10	user_to_fwmgmt	\N	f	2	2025-10-16 23:03:22.37692+07	88	\N	f
1421	10.10.0.11	johndoe	10.10.0.10	user_to_fwmgmt	\N	f	2	2025-10-16 23:03:22.400457+07	88	\N	f
1422	10.10.0.10	\N	10.10.0.11	user_to_fwmgmt	\N	f	2	2025-10-16 23:03:22.431482+07	55818	\N	f
1423	10.10.0.10	\N	10.10.0.11	user_to_fwmgmt	\N	f	2	2025-10-16 23:03:22.455921+07	55818	\N	f
1424	10.10.0.11	johndoe	10.10.0.10	user_to_fwmgmt	\N	f	2	2025-10-16 23:03:22.482228+07	135	\N	f
1425	10.10.0.11	johndoe	10.10.0.10	user_to_fwmgmt	\N	f	2	2025-10-16 23:03:22.514959+07	135	\N	f
1426	10.10.0.11	johndoe	10.10.0.10	user_to_fwmgmt	\N	f	2	2025-10-16 23:03:22.551296+07	135	\N	f
1427	10.10.0.10	\N	10.10.0.11	user_to_fwmgmt	\N	f	2	2025-10-16 23:03:22.584165+07	55819	\N	f
1428	10.10.0.10	\N	10.10.0.11	user_to_fwmgmt	\N	f	2	2025-10-16 23:03:22.606094+07	55819	\N	f
1429	10.10.0.11	johndoe	10.10.0.10	user_to_fwmgmt	\N	f	2	2025-10-16 23:03:22.632207+07	135	\N	f
1430	10.10.0.10	\N	10.10.0.11	user_to_fwmgmt	\N	f	2	2025-10-16 23:03:22.656349+07	55819	\N	f
1431	10.10.0.11	johndoe	10.10.0.10	user_to_fwmgmt	\N	f	2	2025-10-16 23:03:22.680271+07	49667	\N	f
1432	10.10.0.10	\N	10.10.0.11	user_to_fwmgmt	\N	f	2	2025-10-16 23:03:22.70318+07	55820	\N	f
1433	10.10.0.11	johndoe	10.10.0.10	user_to_fwmgmt	\N	f	2	2025-10-16 23:03:22.727555+07	49667	\N	f
1434	10.10.0.11	johndoe	10.10.0.10	user_to_fwmgmt	\N	f	2	2025-10-16 23:03:22.755931+07	88	\N	f
1435	10.10.0.11	johndoe	10.10.0.10	user_to_fwmgmt	\N	f	2	2025-10-16 23:03:22.788419+07	88	\N	f
1436	10.10.0.11	johndoe	10.10.0.10	user_to_fwmgmt	\N	f	2	2025-10-16 23:03:22.821738+07	88	\N	f
1437	10.10.0.11	johndoe	10.10.0.10	user_to_fwmgmt	\N	f	2	2025-10-16 23:03:22.854186+07	88	\N	f
1438	10.10.0.10	\N	10.10.0.11	user_to_fwmgmt	\N	f	2	2025-10-16 23:03:22.879179+07	55821	\N	f
1439	10.10.0.10	\N	10.10.0.11	user_to_fwmgmt	\N	f	2	2025-10-16 23:03:22.90739+07	55821	\N	f
1440	10.10.0.10	\N	10.10.0.11	user_to_fwmgmt	\N	f	2	2025-10-16 23:03:22.929654+07	55821	\N	f
1441	10.10.0.10	\N	10.10.0.11	user_to_fwmgmt	\N	f	2	2025-10-16 23:03:22.956068+07	55821	\N	f
1442	10.10.0.11	johndoe	10.10.0.10	user_to_fwmgmt	\N	f	2	2025-10-16 23:03:22.98159+07	88	\N	f
1443	10.10.0.11	johndoe	10.10.0.10	user_to_fwmgmt	\N	f	2	2025-10-16 23:03:23.003627+07	88	\N	f
1444	10.10.0.10	\N	10.10.0.11	user_to_fwmgmt	\N	f	2	2025-10-16 23:03:23.044422+07	55821	\N	f
1445	10.10.0.10	\N	10.10.0.11	user_to_fwmgmt	\N	f	2	2025-10-16 23:03:23.083308+07	55821	\N	f
1446	10.10.0.11	johndoe	10.10.0.10	user_to_fwmgmt	\N	f	2	2025-10-16 23:03:23.113206+07	49667	\N	f
1447	10.10.0.11	johndoe	10.10.0.10	user_to_fwmgmt	\N	f	2	2025-10-16 23:03:23.142579+07	49667	\N	f
1448	10.10.0.10	\N	10.10.0.11	user_to_fwmgmt	\N	f	2	2025-10-16 23:03:23.183194+07	55820	\N	f
1449	10.10.0.10	\N	10.10.0.11	user_to_fwmgmt	\N	f	2	2025-10-16 23:03:23.229568+07	55820	\N	f
1450	10.10.0.11	johndoe	10.10.0.10	user_to_fwmgmt	\N	f	2	2025-10-16 23:03:23.271187+07	49667	\N	f
1451	10.10.0.10	\N	10.10.0.11	user_to_fwmgmt	\N	f	2	2025-10-16 23:03:23.309286+07	55819	\N	f
1452	10.10.0.11	johndoe	10.10.0.10	user_to_fwmgmt	\N	f	2	2025-10-16 23:03:23.350102+07	135	\N	f
1453	10.10.0.10	\N	10.10.0.11	user_to_fwmgmt	\N	f	2	2025-10-16 23:03:23.37967+07	55820	\N	f
1454	10.10.0.11	johndoe	10.10.0.10	user_to_fwmgmt	\N	f	2	2025-10-16 23:03:23.40311+07	49667	\N	f
1455	10.10.0.10	\N	10.10.0.11	user_to_fwmgmt	\N	f	2	2025-10-16 23:03:23.424685+07	55820	\N	f
1456	10.10.0.11	johndoe	10.10.0.10	user_to_fwmgmt	\N	f	2	2025-10-16 23:03:23.452173+07	49667	\N	f
1457	10.10.0.10	\N	10.10.0.11	user_to_fwmgmt	\N	f	2	2025-10-16 23:03:23.474894+07	55820	\N	f
1458	10.10.0.11	johndoe	10.10.0.10	user_to_fwmgmt	\N	f	2	2025-10-16 23:03:23.497295+07	49667	\N	f
1459	10.10.0.10	\N	10.10.0.11	user_to_fwmgmt	\N	f	2	2025-10-16 23:03:23.521254+07	55820	\N	f
1460	10.10.0.11	johndoe	10.10.0.10	user_to_fwmgmt	\N	f	2	2025-10-16 23:03:23.544425+07	49667	\N	f
1461	10.10.0.10	\N	10.10.0.11	user_to_fwmgmt	\N	f	2	2025-10-16 23:03:23.569949+07	55820	\N	f
1462	10.10.0.11	johndoe	10.10.0.10	user_to_fwmgmt	\N	f	2	2025-10-16 23:03:23.598879+07	135	\N	f
1463	10.10.0.10	\N	10.10.0.11	user_to_fwmgmt	\N	f	2	2025-10-16 23:03:23.625914+07	55819	\N	f
1464	10.10.0.11	johndoe	10.10.0.10	user_to_fwmgmt	\N	f	2	2025-10-16 23:03:23.651861+07	49679	\N	f
1465	10.10.0.10	\N	10.10.0.11	user_to_fwmgmt	\N	f	2	2025-10-16 23:03:23.672066+07	55822	\N	f
1466	10.10.0.11	johndoe	10.10.0.10	user_to_fwmgmt	\N	f	2	2025-10-16 23:03:23.69763+07	49679	\N	f
1467	10.10.0.11	johndoe	10.10.0.10	user_to_fwmgmt	\N	f	2	2025-10-16 23:03:23.720076+07	49679	\N	f
1468	10.10.0.10	\N	10.10.0.11	user_to_fwmgmt	\N	f	2	2025-10-16 23:03:23.743007+07	55822	\N	f
1469	10.10.0.11	johndoe	10.10.0.10	user_to_fwmgmt	\N	f	2	2025-10-16 23:03:23.761609+07	49679	\N	f
1470	10.10.0.10	\N	10.10.0.11	user_to_fwmgmt	\N	f	2	2025-10-16 23:03:23.784709+07	55822	\N	f
1471	10.10.0.10	\N	10.10.0.11	user_to_fwmgmt	\N	f	2	2025-10-16 23:03:23.807045+07	55820	\N	f
1472	10.10.0.10	\N	10.10.0.11	user_to_fwmgmt	\N	f	2	2025-10-16 23:03:23.825878+07	55819	\N	f
1473	10.10.0.11	johndoe	10.10.0.10	user_to_fwmgmt	\N	f	2	2025-10-16 23:03:23.850427+07	49667	\N	f
1474	10.10.0.11	johndoe	10.10.0.10	user_to_fwmgmt	\N	f	2	2025-10-16 23:03:23.876068+07	135	\N	f
1475	10.10.0.10	\N	10.10.0.11	user_to_fwmgmt	\N	f	2	2025-10-16 23:03:23.903392+07	55822	\N	f
1476	10.10.0.11	johndoe	10.10.0.10	user_to_fwmgmt	\N	f	2	2025-10-16 23:03:23.924202+07	49679	\N	f
1477	10.10.0.11	johndoe	10.10.0.10	user_to_fwmgmt	\N	f	2	2025-10-16 23:03:23.946636+07	389	\N	f
1478	10.10.0.11	johndoe	10.10.0.10	user_to_fwmgmt	\N	f	2	2025-10-16 23:03:23.969072+07	389	\N	f
1479	10.10.0.10	\N	10.10.0.11	user_to_fwmgmt	\N	f	2	2025-10-16 23:03:23.986922+07	55823	\N	f
1480	10.10.0.11	johndoe	10.10.0.10	user_to_fwmgmt	\N	f	2	2025-10-16 23:03:24.008902+07	389	\N	f
1481	10.10.0.10	\N	10.10.0.11	user_to_fwmgmt	\N	f	2	2025-10-16 23:03:24.031632+07	55823	\N	f
1482	10.10.0.10	\N	10.10.0.11	user_to_fwmgmt	\N	f	2	2025-10-16 23:03:24.05496+07	55823	\N	f
1483	10.10.0.11	johndoe	10.10.0.10	user_to_fwmgmt	\N	f	2	2025-10-16 23:03:24.0784+07	389	\N	f
1484	10.10.0.11	johndoe	10.10.0.10	user_to_fwmgmt	\N	f	2	2025-10-16 23:03:24.103001+07	389	\N	f
1485	10.10.0.11	johndoe	10.10.0.10	user_to_fwmgmt	\N	f	2	2025-10-16 23:03:24.125312+07	389	\N	f
1486	10.10.0.10	\N	10.10.0.11	user_to_fwmgmt	\N	f	2	2025-10-16 23:03:24.14462+07	55823	\N	f
1487	10.10.0.10	\N	10.10.0.11	user_to_fwmgmt	\N	f	2	2025-10-16 23:03:24.167167+07	55823	\N	f
1488	10.10.0.11	johndoe	10.10.0.10	user_to_fwmgmt	\N	f	2	2025-10-16 23:03:24.185778+07	\N	389	f
1489	10.10.0.10	\N	10.10.0.11	user_to_fwmgmt	\N	f	2	2025-10-16 23:03:24.230863+07	\N	49765	f
1490	10.10.0.10	\N	10.10.0.11	user_to_fwmgmt	\N	f	2	2025-10-16 23:03:24.269312+07	55823	\N	f
1491	10.10.0.11	johndoe	10.10.0.10	user_to_fwmgmt	\N	f	2	2025-10-16 23:03:24.291901+07	389	\N	f
1492	10.10.0.11	johndoe	10.10.0.10	user_to_fwmgmt	\N	f	2	2025-10-16 23:03:24.313769+07	389	\N	f
1493	10.10.0.10	\N	10.10.0.11	user_to_fwmgmt	\N	f	2	2025-10-16 23:03:24.342575+07	55823	\N	f
1494	10.10.0.10	\N	10.10.0.11	user_to_fwmgmt	\N	f	2	2025-10-16 23:03:24.366108+07	\N	49766	f
1495	10.10.0.11	johndoe	10.10.0.10	user_to_fwmgmt	\N	f	2	2025-10-16 23:03:24.392337+07	\N	389	f
1496	10.10.0.10	\N	10.10.0.11	user_to_fwmgmt	\N	f	2	2025-10-16 23:03:24.416176+07	55823	\N	f
1497	10.10.0.11	johndoe	10.10.0.10	user_to_fwmgmt	\N	f	2	2025-10-16 23:03:24.439158+07	389	\N	f
1498	10.10.0.10	\N	10.10.0.11	user_to_fwmgmt	\N	f	2	2025-10-16 23:03:24.462399+07	55824	\N	f
1499	10.10.0.11	johndoe	10.10.0.10	user_to_fwmgmt	\N	f	2	2025-10-16 23:03:24.486637+07	389	\N	f
1500	10.10.0.11	johndoe	10.10.0.10	user_to_fwmgmt	\N	f	2	2025-10-16 23:03:24.505019+07	389	\N	f
1501	10.10.0.11	johndoe	10.10.0.10	user_to_fwmgmt	\N	f	2	2025-10-16 23:03:24.526579+07	389	\N	f
1502	10.10.0.11	johndoe	10.10.0.10	user_to_fwmgmt	\N	f	2	2025-10-16 23:03:24.549562+07	389	\N	f
1503	10.10.0.10	\N	10.10.0.11	user_to_fwmgmt	\N	f	2	2025-10-16 23:03:24.567095+07	55824	\N	f
1504	10.10.0.10	\N	10.10.0.11	user_to_fwmgmt	\N	f	2	2025-10-16 23:03:24.58824+07	55824	\N	f
1505	10.10.0.11	johndoe	10.10.0.10	user_to_fwmgmt	\N	f	2	2025-10-16 23:03:24.609908+07	389	\N	f
1506	10.10.0.10	\N	10.10.0.11	user_to_fwmgmt	\N	f	2	2025-10-16 23:03:24.635351+07	55824	\N	f
1507	10.10.0.11	johndoe	10.10.0.10	user_to_fwmgmt	\N	f	2	2025-10-16 23:03:24.659542+07	389	\N	f
1508	10.10.0.10	\N	10.10.0.11	user_to_fwmgmt	\N	f	2	2025-10-16 23:03:24.685364+07	55824	\N	f
1509	10.10.0.11	johndoe	10.10.0.10	user_to_fwmgmt	\N	f	2	2025-10-16 23:03:24.707723+07	389	\N	f
1510	10.10.0.10	\N	10.10.0.11	user_to_fwmgmt	\N	f	2	2025-10-16 23:03:24.731008+07	55823	\N	f
1511	10.10.0.10	\N	10.10.0.11	user_to_fwmgmt	\N	f	2	2025-10-16 23:03:24.752743+07	55824	\N	f
1512	10.10.0.10	\N	10.10.0.11	user_to_fwmgmt	\N	f	2	2025-10-16 23:03:24.778165+07	55823	\N	f
1513	10.10.0.11	johndoe	10.10.0.10	user_to_fwmgmt	\N	f	2	2025-10-16 23:03:24.80363+07	389	\N	f
1514	10.10.0.11	johndoe	10.10.0.10	user_to_fwmgmt	\N	f	2	2025-10-16 23:03:24.826334+07	389	\N	f
1515	10.10.0.11	johndoe	10.10.0.10	user_to_fwmgmt	\N	f	2	2025-10-16 23:03:24.847518+07	389	\N	f
1516	10.10.0.11	johndoe	10.10.0.10	user_to_fwmgmt	\N	f	2	2025-10-16 23:03:24.873659+07	389	\N	f
1517	10.10.0.10	\N	10.10.0.11	user_to_fwmgmt	\N	f	2	2025-10-16 23:03:24.897275+07	55824	\N	f
1518	10.10.0.10	\N	10.10.0.11	user_to_fwmgmt	\N	f	2	2025-10-16 23:03:24.91748+07	55824	\N	f
1519	10.10.0.11	johndoe	10.10.0.10	user_to_fwmgmt	\N	f	2	2025-10-16 23:03:24.94963+07	389	\N	f
1520	10.10.0.10	\N	10.10.0.11	user_to_fwmgmt	\N	f	2	2025-10-16 23:03:24.9756+07	55823	\N	f
1521	10.10.0.10	\N	10.10.0.11	user_to_fwmgmt	\N	f	2	2025-10-16 23:03:25.002774+07	55823	\N	f
1522	10.10.0.11	johndoe	10.10.0.10	user_to_fwmgmt	\N	f	2	2025-10-16 23:03:25.0287+07	389	\N	f
1523	10.10.0.10	\N	10.10.10.10	AD_to_Ctrl	2	t	2	2025-10-16 23:03:25.054688+07	21012	\N	f
1524	10.10.0.10	\N	10.10.10.10	AD_to_Ctrl	2	t	2	2025-10-16 23:03:26.100717+07	21012	\N	f
1525	10.10.0.11	johndoe	10.10.10.10	All_to_DNS	1	t	2	2025-10-16 23:03:26.28057+07	\N	53	f
1526	10.10.0.11	johndoe	10.10.0.10	user_to_fwmgmt	\N	f	2	2025-10-16 23:03:26.433162+07	\N	53	f
1527	10.10.0.10	\N	1.1.1.1	user_to_fwmgmt	\N	f	2	2025-10-16 23:03:26.461567+07	\N	53	f
1528	10.10.0.11	johndoe	10.10.0.10	user_to_fwmgmt	\N	f	2	2025-10-16 23:03:26.747639+07	389	\N	f
1529	10.10.0.10	\N	10.10.0.11	user_to_fwmgmt	\N	f	2	2025-10-16 23:03:26.772731+07	55825	\N	f
1530	10.10.0.11	johndoe	10.10.0.10	user_to_fwmgmt	\N	f	2	2025-10-16 23:03:26.800547+07	389	\N	f
1531	10.10.0.11	johndoe	10.10.0.10	user_to_fwmgmt	\N	f	2	2025-10-16 23:03:26.820179+07	389	\N	f
1532	10.10.0.10	\N	10.10.0.11	user_to_fwmgmt	\N	f	2	2025-10-16 23:03:26.844607+07	55825	\N	f
1533	10.10.0.10	\N	10.10.0.11	user_to_fwmgmt	\N	f	2	2025-10-16 23:03:26.868287+07	55825	\N	f
1534	10.10.0.11	johndoe	10.10.0.10	user_to_fwmgmt	\N	f	2	2025-10-16 23:03:26.897063+07	389	\N	f
1535	10.10.0.11	johndoe	10.10.0.10	user_to_fwmgmt	\N	f	2	2025-10-16 23:03:26.924386+07	389	\N	f
1536	10.10.0.11	johndoe	10.10.0.10	user_to_fwmgmt	\N	f	2	2025-10-16 23:03:26.949692+07	389	\N	f
1537	10.10.0.10	\N	10.10.0.11	user_to_fwmgmt	\N	f	2	2025-10-16 23:03:26.972675+07	55825	\N	f
1538	10.10.0.10	\N	10.10.0.11	user_to_fwmgmt	\N	f	2	2025-10-16 23:03:26.993629+07	55825	\N	f
1539	10.10.0.11	johndoe	10.10.0.10	user_to_fwmgmt	\N	f	2	2025-10-16 23:03:27.017619+07	389	\N	f
1540	10.10.0.10	\N	10.10.0.11	user_to_fwmgmt	\N	f	2	2025-10-16 23:03:27.040206+07	55825	\N	f
1541	10.10.0.10	\N	10.10.0.11	user_to_fwmgmt	\N	f	2	2025-10-16 23:03:27.063257+07	55825	\N	f
1542	10.10.0.10	\N	10.10.0.11	user_to_fwmgmt	\N	f	2	2025-10-16 23:03:27.08478+07	55825	\N	f
1543	10.10.0.11	johndoe	10.10.0.10	user_to_fwmgmt	\N	f	2	2025-10-16 23:03:27.108352+07	389	\N	f
1544	10.10.0.11	johndoe	10.10.0.10	user_to_fwmgmt	\N	f	2	2025-10-16 23:03:27.133039+07	389	\N	f
1545	10.10.0.10	\N	10.10.0.11	user_to_fwmgmt	\N	f	2	2025-10-16 23:03:27.153039+07	55825	\N	f
1546	10.10.0.10	\N	10.10.0.11	user_to_fwmgmt	\N	f	2	2025-10-16 23:03:27.172281+07	55825	\N	f
1547	10.10.0.10	\N	10.10.0.11	user_to_fwmgmt	\N	f	2	2025-10-16 23:03:27.193385+07	55825	\N	f
1548	10.10.0.10	\N	10.10.0.11	user_to_fwmgmt	\N	f	2	2025-10-16 23:03:27.219108+07	55825	\N	f
1549	10.10.0.10	\N	10.10.0.11	user_to_fwmgmt	\N	f	2	2025-10-16 23:03:27.240827+07	55825	\N	f
1550	10.10.0.11	johndoe	113.171.230.149	user_to_fwmgmt	\N	f	2	2025-10-16 23:03:27.425293+07	443	\N	f
1551	10.10.0.11	johndoe	74.178.240.61	user_to_fwmgmt	\N	f	2	2025-10-16 23:03:28.037749+07	443	\N	f
1552	10.10.0.10	\N	10.10.10.10	AD_to_Ctrl	2	t	2	2025-10-16 23:03:29.238496+07	21012	\N	f
1553	10.10.0.11	johndoe	113.171.230.142	user_to_fwmgmt	\N	f	2	2025-10-16 23:03:34.473747+07	443	\N	f
1554	10.10.0.11	johndoe	20.210.166.59	user_to_fwmgmt	\N	f	2	2025-10-16 23:03:35.750959+07	443	\N	f
1555	10.10.0.10	\N	10.10.0.11	user_to_fwmgmt	\N	f	2	2025-10-16 23:03:35.938222+07	\N	63112	f
1556	10.10.0.10	\N	74.178.240.61	user_to_fwmgmt	\N	f	2	2025-10-16 23:03:40.291116+07	443	\N	f
1557	10.10.0.1	\N	224.0.0.251	user_to_fwmgmt	\N	f	2	2025-10-16 23:03:47.216509+07	\N	5353	f
1558	10.10.0.1	\N	224.0.0.251	user_to_fwmgmt	\N	f	2	2025-10-16 23:03:47.240253+07	\N	5353	f
1559	192.168.230.1	\N	224.0.0.251	user_to_fwmgmt	\N	f	1	2025-10-16 23:03:47.255383+07	\N	5353	f
1560	192.168.230.1	\N	224.0.0.251	user_to_fwmgmt	\N	f	1	2025-10-16 23:03:47.27038+07	\N	5353	f
1561	10.20.0.1	\N	224.0.0.251	user_to_fwmgmt	\N	f	3	2025-10-16 23:03:47.290939+07	\N	5353	f
1562	10.20.0.1	\N	224.0.0.251	user_to_fwmgmt	\N	f	3	2025-10-16 23:03:47.307283+07	\N	5353	f
1563	10.10.0.11	johndoe	74.178.240.61	user_to_fwmgmt	\N	f	2	2025-10-16 23:03:49.081814+07	443	\N	f
1564	10.10.0.10	\N	1.1.1.1	user_to_fwmgmt	\N	f	2	2025-10-16 23:03:50.887024+07	\N	53	f
1565	10.10.0.10	\N	10.10.10.10	All_to_DNS	1	t	2	2025-10-16 23:03:51.911701+07	\N	53	f
1566	10.10.0.10	\N	1.1.1.1	user_to_fwmgmt	\N	f	2	2025-10-16 23:03:54.96889+07	\N	53	f
1567	10.10.0.10	\N	172.178.240.163	user_to_fwmgmt	\N	f	2	2025-10-16 23:03:54.986517+07	443	\N	f
1568	10.10.0.10	\N	74.178.240.61	user_to_fwmgmt	\N	f	2	2025-10-16 23:04:01.367045+07	443	\N	f
1569	10.10.0.11	johndoe	74.178.240.61	user_to_fwmgmt	\N	f	2	2025-10-16 23:04:10.273494+07	443	\N	f
1570	10.10.0.11	johndoe	10.10.10.10	user_to_fwmgmt	9	t	2	2025-10-16 23:04:11.141664+07	8000	\N	f
1571	10.10.0.11	johndoe	10.10.10.10	All_to_DNS	1	t	2	2025-10-16 23:04:11.518817+07	\N	53	f
1572	10.10.0.11	johndoe	10.10.0.10	user_to_fwmgmt	\N	f	2	2025-10-16 23:04:11.648819+07	\N	53	f
1573	10.10.0.10	\N	10.10.0.11	user_to_fwmgmt	\N	f	2	2025-10-16 23:04:11.68154+07	\N	53779	f
1574	10.10.0.10	\N	1.1.1.1	user_to_fwmgmt	\N	f	2	2025-10-16 23:04:16.094463+07	\N	53	f
1575	10.10.0.10	\N	10.10.10.10	All_to_DNS	1	t	2	2025-10-16 23:04:17.072834+07	\N	53	f
1576	10.10.0.10	\N	172.178.240.163	user_to_fwmgmt	\N	f	2	2025-10-16 23:04:20.119136+07	443	\N	f
1577	10.10.0.10	\N	74.178.240.61	user_to_fwmgmt	\N	f	2	2025-10-16 23:04:22.398511+07	443	\N	f
1578	10.10.0.11	johndoe	135.233.95.144	user_to_fwmgmt	\N	f	2	2025-10-16 23:04:31.361576+07	443	\N	f
1579	10.10.0.11	johndoe	10.10.10.10	user_to_fwmgmt	9	t	2	2025-10-16 23:04:36.381444+07	8000	\N	f
1580	10.10.0.10	\N	1.1.1.1	user_to_fwmgmt	\N	f	2	2025-10-16 23:04:41.193869+07	\N	53	f
1581	10.10.0.10	\N	10.10.10.10	All_to_DNS	1	t	2	2025-10-16 23:04:42.192976+07	\N	53	f
1582	10.10.0.10	\N	1.1.1.1	user_to_fwmgmt	\N	f	2	2025-10-16 23:04:43.484872+07	\N	53	f
1583	10.10.0.10	\N	74.179.77.204	user_to_fwmgmt	\N	f	2	2025-10-16 23:04:44.529658+07	443	\N	f
1584	10.10.0.10	\N	1.1.1.1	user_to_fwmgmt	\N	f	2	2025-10-16 23:04:45.212153+07	\N	53	f
1585	10.10.0.10	\N	135.234.160.244	user_to_fwmgmt	\N	f	2	2025-10-16 23:04:45.239654+07	443	\N	f
1586	10.10.0.10	\N	10.10.0.255	user_to_fwmgmt	\N	f	2	2025-10-16 23:04:47.196402+07	\N	138	f
1587	10.10.0.10	\N	192.203.230.10	user_to_fwmgmt	\N	f	2	2025-10-16 23:04:47.602203+07	\N	53	f
1588	10.10.0.10	\N	192.112.36.4	user_to_fwmgmt	\N	f	2	2025-10-16 23:04:49.404662+07	\N	53	f
1589	10.10.0.11	johndoe	135.233.95.144	user_to_fwmgmt	\N	f	2	2025-10-16 23:04:52.429016+07	443	\N	f
1590	10.10.0.10	\N	74.179.77.204	user_to_fwmgmt	\N	f	2	2025-10-16 23:05:05.544101+07	443	\N	f
1591	10.10.0.10	\N	1.1.1.1	user_to_fwmgmt	\N	f	2	2025-10-16 23:05:06.346134+07	\N	53	f
1592	10.10.0.10	\N	10.10.10.10	All_to_DNS	1	t	2	2025-10-16 23:05:07.311159+07	\N	53	f
1593	10.10.0.10	\N	1.1.1.1	user_to_fwmgmt	\N	f	2	2025-10-16 23:05:10.339648+07	\N	53	f
1594	10.10.0.10	\N	135.234.160.244	user_to_fwmgmt	\N	f	2	2025-10-16 23:05:10.356347+07	443	\N	f
1595	10.10.0.11	johndoe	135.233.95.144	user_to_fwmgmt	\N	f	2	2025-10-16 23:05:13.454984+07	443	\N	f
1596	10.10.0.10	\N	192.203.230.10	user_to_fwmgmt	\N	f	2	2025-10-16 23:05:13.937133+07	\N	53	f
1597	10.10.0.10	\N	1.1.1.1	user_to_fwmgmt	\N	f	2	2025-10-16 23:05:26.5886+07	\N	53	f
1598	10.10.0.10	\N	10.10.10.10	All_to_DNS	1	t	2	2025-10-16 23:05:27.578266+07	\N	53	f
1599	10.10.0.10	\N	1.1.1.1	user_to_fwmgmt	\N	f	2	2025-10-16 23:05:30.622528+07	\N	53	f
1600	10.10.0.10	\N	74.178.76.128	user_to_fwmgmt	\N	f	2	2025-10-16 23:05:30.65349+07	443	\N	f
1601	10.10.0.10	\N	1.1.1.1	user_to_fwmgmt	\N	f	2	2025-10-16 23:05:31.453457+07	\N	53	f
1602	10.10.0.10	\N	135.233.45.222	user_to_fwmgmt	\N	f	2	2025-10-16 23:05:32.451158+07	443	\N	f
1603	10.10.0.11	johndoe	135.233.95.144	user_to_fwmgmt	\N	f	2	2025-10-16 23:05:34.468754+07	443	\N	f
1604	10.10.0.1	\N	224.0.0.251	user_to_fwmgmt	\N	f	2	2025-10-16 23:05:48.013541+07	\N	5353	f
1605	192.168.230.1	\N	224.0.0.251	user_to_fwmgmt	\N	f	1	2025-10-16 23:05:48.031437+07	\N	5353	f
1606	192.168.230.1	\N	224.0.0.251	user_to_fwmgmt	\N	f	1	2025-10-16 23:05:48.050584+07	\N	5353	f
1607	10.20.0.1	\N	224.0.0.251	user_to_fwmgmt	\N	f	3	2025-10-16 23:05:48.069258+07	\N	5353	f
1608	10.20.0.1	\N	224.0.0.251	user_to_fwmgmt	\N	f	3	2025-10-16 23:05:48.087268+07	\N	5353	f
1609	10.10.0.1	\N	224.0.0.251	user_to_fwmgmt	\N	f	2	2025-10-16 23:05:48.109134+07	\N	5353	f
1610	10.10.0.10	\N	74.178.76.128	user_to_fwmgmt	\N	f	2	2025-10-16 23:05:51.66423+07	443	\N	f
1611	10.10.0.10	\N	1.1.1.1	user_to_fwmgmt	\N	f	2	2025-10-16 23:05:53.578918+07	\N	53	f
1612	10.10.0.10	\N	10.10.10.10	All_to_DNS	1	t	2	2025-10-16 23:05:54.537155+07	\N	53	f
1613	10.10.0.11	johndoe	135.233.95.144	user_to_fwmgmt	\N	f	2	2025-10-16 23:05:55.555114+07	443	\N	f
1614	10.10.0.10	\N	1.1.1.1	user_to_fwmgmt	\N	f	2	2025-10-16 23:05:57.564956+07	\N	53	f
1615	10.10.0.10	\N	135.233.45.222	user_to_fwmgmt	\N	f	2	2025-10-16 23:05:57.587127+07	443	\N	f
1616	10.10.0.10	\N	192.203.230.10	user_to_fwmgmt	\N	f	2	2025-10-16 23:06:01.105167+07	\N	53	f
1617	10.10.0.10	\N	74.178.76.128	user_to_fwmgmt	\N	f	2	2025-10-16 23:06:12.686527+07	443	\N	f
1618	10.10.0.11	johndoe	135.233.95.144	user_to_fwmgmt	\N	f	2	2025-10-16 23:06:16.622363+07	443	\N	f
1619	10.10.0.10	\N	1.1.1.1	user_to_fwmgmt	\N	f	2	2025-10-16 23:06:18.691258+07	\N	53	f
1620	10.10.0.10	\N	10.10.10.10	All_to_DNS	1	t	2	2025-10-16 23:06:19.686014+07	\N	53	f
1621	10.10.0.10	\N	1.1.1.1	user_to_fwmgmt	\N	f	2	2025-10-16 23:06:22.707364+07	\N	53	f
1622	10.10.0.10	\N	135.233.45.221	user_to_fwmgmt	\N	f	2	2025-10-16 23:06:22.730719+07	443	\N	f
1623	10.10.0.10	\N	74.178.76.128	user_to_fwmgmt	\N	f	2	2025-10-16 23:06:33.712014+07	443	\N	f
1624	10.10.0.11	johndoe	135.233.95.144	user_to_fwmgmt	\N	f	2	2025-10-16 23:06:37.677867+07	443	\N	f
1625	10.10.0.11	johndoe	10.10.10.10	user_to_fwmgmt	9	t	2	2025-10-16 23:06:39.751536+07	8000	\N	f
1626	10.10.0.10	\N	74.178.76.128	user_to_fwmgmt	\N	f	2	2025-10-16 23:06:54.764549+07	443	\N	f
1627	10.10.0.11	johndoe	10.10.0.10	user_to_fwmgmt	\N	f	2	2025-10-16 23:06:55.197573+07	\N	123	f
1628	10.10.0.10	\N	10.10.0.11	user_to_fwmgmt	\N	f	2	2025-10-16 23:06:55.221126+07	\N	123	f
1629	10.10.0.11	johndoe	135.233.95.144	user_to_fwmgmt	\N	f	2	2025-10-16 23:06:58.882647+07	443	\N	f
1630	10.10.0.11	johndoe	10.10.10.10	All_to_DNS	1	t	2	2025-10-16 23:06:58.960123+07	\N	53	f
1631	10.10.0.11	johndoe	10.10.0.10	user_to_fwmgmt	\N	f	2	2025-10-16 23:06:59.057854+07	\N	53	f
1632	10.10.0.10	\N	1.1.1.1	user_to_fwmgmt	\N	f	2	2025-10-16 23:06:59.073285+07	\N	53	f
1633	10.10.0.11	johndoe	23.53.210.10	user_to_fwmgmt	\N	f	2	2025-10-16 23:07:00.121061+07	443	\N	f
1634	10.10.0.10	\N	192.203.230.10	user_to_fwmgmt	\N	f	2	2025-10-16 23:07:01.893942+07	\N	53	f
1635	10.10.0.10	\N	10.10.0.11	user_to_fwmgmt	\N	f	2	2025-10-16 23:07:08.316605+07	\N	57296	f
1636	10.10.0.10	\N	52.123.129.14	user_to_fwmgmt	\N	f	2	2025-10-16 23:07:12.213799+07	443	\N	f
1637	10.10.0.10	\N	74.178.76.128	user_to_fwmgmt	\N	f	2	2025-10-16 23:07:15.805013+07	443	\N	f
1638	10.10.0.11	johndoe	135.233.95.144	user_to_fwmgmt	\N	f	2	2025-10-16 23:07:19.913801+07	443	\N	f
1639	10.10.0.11	johndoe	10.10.10.10	All_to_DNS	1	t	2	2025-10-16 23:07:21.173691+07	\N	53	f
1640	10.10.0.11	johndoe	10.10.0.10	user_to_fwmgmt	\N	f	2	2025-10-16 23:07:21.242194+07	\N	53	f
1641	10.10.0.10	\N	1.1.1.1	user_to_fwmgmt	\N	f	2	2025-10-16 23:07:21.263796+07	\N	53	f
1642	10.10.0.11	johndoe	23.53.210.10	user_to_fwmgmt	\N	f	2	2025-10-16 23:07:22.274844+07	443	\N	f
1643	10.10.0.10	\N	10.10.0.11	user_to_fwmgmt	\N	f	2	2025-10-16 23:07:30.980485+07	\N	54562	f
1644	10.10.0.10	\N	52.123.128.14	user_to_fwmgmt	\N	f	2	2025-10-16 23:07:33.234529+07	443	\N	f
1645	10.10.0.10	\N	74.178.76.128	user_to_fwmgmt	\N	f	2	2025-10-16 23:07:36.851223+07	443	\N	f
1646	10.10.0.11	johndoe	135.233.95.144	user_to_fwmgmt	\N	f	2	2025-10-16 23:07:40.968808+07	443	\N	f
1647	10.10.0.11	johndoe	10.10.10.10	All_to_DNS	1	t	2	2025-10-16 23:07:43.363865+07	\N	53	f
1648	10.10.0.11	johndoe	10.10.0.10	user_to_fwmgmt	\N	f	2	2025-10-16 23:07:43.414772+07	\N	53	f
1649	10.10.0.10	\N	1.1.1.1	user_to_fwmgmt	\N	f	2	2025-10-16 23:07:43.432892+07	\N	53	f
1650	10.10.0.11	johndoe	23.53.210.10	user_to_fwmgmt	\N	f	2	2025-10-16 23:07:44.460681+07	443	\N	f
1651	192.168.230.1	\N	224.0.0.251	user_to_fwmgmt	\N	f	1	2025-10-16 23:07:48.844969+07	\N	5353	f
1652	192.168.230.1	\N	224.0.0.251	user_to_fwmgmt	\N	f	1	2025-10-16 23:07:48.865651+07	\N	5353	f
1653	10.20.0.1	\N	224.0.0.251	user_to_fwmgmt	\N	f	3	2025-10-16 23:07:48.882159+07	\N	5353	f
1654	10.20.0.1	\N	224.0.0.251	user_to_fwmgmt	\N	f	3	2025-10-16 23:07:48.901265+07	\N	5353	f
1655	10.10.0.1	\N	224.0.0.251	user_to_fwmgmt	\N	f	2	2025-10-16 23:07:48.923655+07	\N	5353	f
1656	10.10.0.1	\N	224.0.0.251	user_to_fwmgmt	\N	f	2	2025-10-16 23:07:48.939193+07	\N	5353	f
1657	10.10.0.10	\N	10.10.0.11	user_to_fwmgmt	\N	f	2	2025-10-16 23:07:52.743924+07	\N	51273	f
1658	10.10.0.10	\N	74.178.76.128	user_to_fwmgmt	\N	f	2	2025-10-16 23:07:57.853926+07	443	\N	f
\.


--
-- Data for Name: policy; Type: TABLE DATA; Schema: public; Owner: srv_acc
--

COPY public.policy (id, name, srcip, srcuser, dstip, tcp_ports, udp_ports, icmp, action, disabled, schedule, order_index, domains) FROM stdin;
1	All_to_DNS	{}	{}	{10.10.10.10}	\N	{53}	t	t	f	\N	1	\N
2	AD_to_Ctrl	{10.10.0.10}	{}	{10.10.10.10}	{21012}	\N	f	t	f	\N	2	\N
3	Usr_to_Cloudfare	{}	{johndoe}	{1.1.1.1}	{80}	\N	t	t	f	\N	3	\N
4	Usr_to_DNSggl	{}	{"Domain Users"}	{}	\N	\N	t	t	f	\N	4	{dns.google}
5	Inbound ICMP	{}	{}	{192.168.230.155}	\N	\N	t	t	f	\N	5	\N
9	user_to_fwmgmt	{}	{fw_controller_access}	{10.10.10.10}	{8000}	\N	f	t	f	\N	6	\N
\.


--
-- Data for Name: users; Type: TABLE DATA; Schema: public; Owner: srv_acc
--

COPY public.users (id, username, password_hash, user_mgmt, policy_mgmt, user_view, policy_view) FROM stdin;
1	admin	scrypt:32768:8:1$gokpvJw2pRBgTxc8$9927d29b5bfa1a4010ac57930d6275b8dcae37d56d95cac06dbf7f86a1a6258e67c8502fc3ddfb88431cf5984c858bab1c5baff276e1ccd31bd12f2fc8cfb91b	t	t	t	t
\.


--
-- Name: logs_id_seq; Type: SEQUENCE SET; Schema: public; Owner: srv_acc
--

SELECT pg_catalog.setval('public.logs_id_seq', 1658, true);


--
-- Name: policy_id_seq; Type: SEQUENCE SET; Schema: public; Owner: srv_acc
--

SELECT pg_catalog.setval('public.policy_id_seq', 9, true);


--
-- Name: users_id_seq; Type: SEQUENCE SET; Schema: public; Owner: srv_acc
--

SELECT pg_catalog.setval('public.users_id_seq', 1, true);


--
-- Name: logs logs_pkey; Type: CONSTRAINT; Schema: public; Owner: srv_acc
--

ALTER TABLE ONLY public.logs
    ADD CONSTRAINT logs_pkey PRIMARY KEY (id);


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
-- Name: logs logs_ruleid_fkey; Type: FK CONSTRAINT; Schema: public; Owner: srv_acc
--

ALTER TABLE ONLY public.logs
    ADD CONSTRAINT logs_ruleid_fkey FOREIGN KEY (ruleid) REFERENCES public.policy(id) ON DELETE SET NULL;


--
-- PostgreSQL database dump complete
--

\unrestrict gyHjRanzgBKcHLYbyg9hUMOFucVnnEM5gSFdJPfTrhAXxsl24RyGiT1rwxtnqKS

--
-- Database "postgres" dump
--

\connect postgres

--
-- PostgreSQL database dump
--

\restrict rLfRLWo5VVVNBWgkXH6obfTOQvSrmpGKnCPVdj4zB5rLcJCIco6joNlw53TWDRT

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

\unrestrict rLfRLWo5VVVNBWgkXH6obfTOQvSrmpGKnCPVdj4zB5rLcJCIco6joNlw53TWDRT

--
-- PostgreSQL database cluster dump complete
--

