-- phpMyAdmin SQL Dump
-- version 2.11.10
-- http://www.phpmyadmin.net
--
-- 主机: localhost
-- 生成日期: 2010 年 06 月 12 日 06:24
-- 服务器版本: 5.0.77
-- PHP 版本: 5.1.6

SET SQL_MODE="NO_AUTO_VALUE_ON_ZERO";


/*!40101 SET @OLD_CHARACTER_SET_CLIENT=@@CHARACTER_SET_CLIENT */;
/*!40101 SET @OLD_CHARACTER_SET_RESULTS=@@CHARACTER_SET_RESULTS */;
/*!40101 SET @OLD_COLLATION_CONNECTION=@@COLLATION_CONNECTION */;
/*!40101 SET NAMES utf8 */;

--
-- 数据库: `snort`
--

-- --------------------------------------------------------

--
-- 表的结构 `approto`
--

CREATE TABLE IF NOT EXISTS `approto` (
  `id` int(10) unsigned NOT NULL auto_increment,
  `time` int(10) unsigned NOT NULL,
  `ip` int(10) unsigned NOT NULL,
  `port` smallint(5) unsigned NOT NULL,
  `proto` varchar(255) NOT NULL,
  PRIMARY KEY  (`id`)
) ENGINE=MyISAM DEFAULT CHARSET=latin1 AUTO_INCREMENT=1 ;

--
-- 导出表中的数据 `approto`
--


-- --------------------------------------------------------

--
-- 表的结构 `custom_rule`
--

CREATE TABLE IF NOT EXISTS `custom_rule` (
  `id` int(11) default NULL,
  `type` int(11) default NULL,
  `rule` varchar(256) default NULL,
  `proto` varchar(32) default NULL
) ENGINE=MyISAM DEFAULT CHARSET=latin1;

--
-- 导出表中的数据 `custom_rule`
--

INSERT INTO `custom_rule` (`id`, `type`, `rule`, `proto`) VALUES
(1, 1, '1_rule_test', ''),
(2, 1, '2_rule_test', NULL),
(3, 2, '3_rule_test', 'rule_L7_1'),
(4, 2, '4_rule_test', 'rule_L7_2');

-- --------------------------------------------------------

--
-- 表的结构 `data`
--

CREATE TABLE IF NOT EXISTS `data` (
  `sid` int(10) unsigned NOT NULL,
  `cid` int(10) unsigned NOT NULL,
  `data_payload` text,
  PRIMARY KEY  (`sid`,`cid`)
) ENGINE=MyISAM DEFAULT CHARSET=latin1;

--
-- 导出表中的数据 `data`
--

INSERT INTO `data` (`sid`, `cid`, `data_payload`) VALUES
(1, 1, '6162636465666768696A6B6C6D6E6F7071727374757677616263646566676869'),
(1, 2, '6162636465666768696A6B6C6D6E6F7071727374757677616263646566676869'),
(1, 3, '6162636465666768696A6B6C6D6E6F7071727374757677616263646566676869'),
(1, 4, '6162636465666768696A6B6C6D6E6F7071727374757677616263646566676869'),
(1, 5, '6162636465666768696A6B6C6D6E6F7071727374757677616263646566676869'),
(1, 6, '6162636465666768696A6B6C6D6E6F7071727374757677616263646566676869'),
(1, 7, '6162636465666768696A6B6C6D6E6F7071727374757677616263646566676869'),
(1, 8, '6162636465666768696A6B6C6D6E6F7071727374757677616263646566676869'),
(1, 9, '6162636465666768696A6B6C6D6E6F7071727374757677616263646566676869'),
(1, 10, '6162636465666768696A6B6C6D6E6F7071727374757677616263646566676869'),
(1, 11, '6162636465666768696A6B6C6D6E6F7071727374757677616263646566676869'),
(1, 12, '6162636465666768696A6B6C6D6E6F7071727374757677616263646566676869'),
(1, 13, '6162636465666768696A6B6C6D6E6F7071727374757677616263646566676869'),
(1, 14, '6162636465666768696A6B6C6D6E6F7071727374757677616263646566676869'),
(1, 15, '6162636465666768696A6B6C6D6E6F7071727374757677616263646566676869'),
(1, 16, '6162636465666768696A6B6C6D6E6F7071727374757677616263646566676869'),
(1, 17, '6162636465666768696A6B6C6D6E6F7071727374757677616263646566676869'),
(1, 18, '6162636465666768696A6B6C6D6E6F7071727374757677616263646566676869'),
(1, 19, '6162636465666768696A6B6C6D6E6F7071727374757677616263646566676869'),
(1, 20, '6162636465666768696A6B6C6D6E6F7071727374757677616263646566676869'),
(1, 21, '6162636465666768696A6B6C6D6E6F7071727374757677616263646566676869'),
(1, 22, '6162636465666768696A6B6C6D6E6F7071727374757677616263646566676869'),
(1, 23, '6162636465666768696A6B6C6D6E6F7071727374757677616263646566676869'),
(1, 24, '6162636465666768696A6B6C6D6E6F7071727374757677616263646566676869'),
(1, 25, '6162636465666768696A6B6C6D6E6F7071727374757677616263646566676869'),
(1, 26, '6162636465666768696A6B6C6D6E6F7071727374757677616263646566676869'),
(1, 27, '6162636465666768696A6B6C6D6E6F7071727374757677616263646566676869'),
(1, 28, '6162636465666768696A6B6C6D6E6F7071727374757677616263646566676869'),
(1, 29, '6162636465666768696A6B6C6D6E6F7071727374757677616263646566676869'),
(1, 30, '6162636465666768696A6B6C6D6E6F7071727374757677616263646566676869'),
(1, 31, '6162636465666768696A6B6C6D6E6F7071727374757677616263646566676869'),
(1, 32, '6162636465666768696A6B6C6D6E6F7071727374757677616263646566676869'),
(1, 33, '6162636465666768696A6B6C6D6E6F7071727374757677616263646566676869'),
(1, 34, '6162636465666768696A6B6C6D6E6F7071727374757677616263646566676869'),
(1, 35, '6162636465666768696A6B6C6D6E6F7071727374757677616263646566676869'),
(1, 36, '6162636465666768696A6B6C6D6E6F7071727374757677616263646566676869');

-- --------------------------------------------------------

--
-- 表的结构 `detail`
--

CREATE TABLE IF NOT EXISTS `detail` (
  `detail_type` tinyint(3) unsigned NOT NULL,
  `detail_text` text NOT NULL,
  PRIMARY KEY  (`detail_type`)
) ENGINE=MyISAM DEFAULT CHARSET=latin1;

--
-- 导出表中的数据 `detail`
--

INSERT INTO `detail` (`detail_type`, `detail_text`) VALUES
(0, 'fast'),
(1, 'full');

-- --------------------------------------------------------

--
-- 表的结构 `encoding`
--

CREATE TABLE IF NOT EXISTS `encoding` (
  `encoding_type` tinyint(3) unsigned NOT NULL,
  `encoding_text` text NOT NULL,
  PRIMARY KEY  (`encoding_type`)
) ENGINE=MyISAM DEFAULT CHARSET=latin1;

--
-- 导出表中的数据 `encoding`
--

INSERT INTO `encoding` (`encoding_type`, `encoding_text`) VALUES
(0, 'hex'),
(1, 'base64'),
(2, 'ascii');

-- --------------------------------------------------------

--
-- 表的结构 `event`
--

CREATE TABLE IF NOT EXISTS `event` (
  `sid` int(10) unsigned NOT NULL,
  `cid` int(10) unsigned NOT NULL,
  `signature` int(10) unsigned NOT NULL,
  `timestamp` datetime NOT NULL,
  PRIMARY KEY  (`sid`,`cid`),
  KEY `sig` (`signature`),
  KEY `time` (`timestamp`)
) ENGINE=MyISAM DEFAULT CHARSET=latin1;

--
-- 导出表中的数据 `event`
--

INSERT INTO `event` (`sid`, `cid`, `signature`, `timestamp`) VALUES
(1, 1, 1, '2010-06-10 08:32:15'),
(1, 2, 2, '2010-06-10 08:32:15'),
(1, 3, 3, '2010-06-10 08:32:15'),
(1, 4, 1, '2010-06-10 08:32:16'),
(1, 5, 2, '2010-06-10 08:32:16'),
(1, 6, 3, '2010-06-10 08:32:16'),
(1, 7, 1, '2010-06-10 08:32:17'),
(1, 8, 2, '2010-06-10 08:32:17'),
(1, 9, 3, '2010-06-10 08:32:17'),
(1, 10, 1, '2010-06-10 08:32:18'),
(1, 11, 2, '2010-06-10 08:32:18'),
(1, 12, 3, '2010-06-10 08:32:18'),
(1, 13, 1, '2010-06-11 23:42:18'),
(1, 14, 2, '2010-06-11 23:42:18'),
(1, 15, 3, '2010-06-11 23:42:18'),
(1, 16, 1, '2010-06-11 23:42:19'),
(1, 17, 2, '2010-06-11 23:42:19'),
(1, 18, 3, '2010-06-11 23:42:19'),
(1, 19, 1, '2010-06-11 23:42:20'),
(1, 20, 2, '2010-06-11 23:42:20'),
(1, 21, 3, '2010-06-11 23:42:20'),
(1, 22, 1, '2010-06-11 23:42:21'),
(1, 23, 2, '2010-06-11 23:42:21'),
(1, 24, 3, '2010-06-11 23:42:21'),
(1, 25, 1, '2010-06-12 04:27:27'),
(1, 26, 2, '2010-06-12 04:27:27'),
(1, 27, 3, '2010-06-12 04:27:27'),
(1, 28, 1, '2010-06-12 04:27:28'),
(1, 29, 2, '2010-06-12 04:27:28'),
(1, 30, 3, '2010-06-12 04:27:28'),
(1, 31, 1, '2010-06-12 04:27:29'),
(1, 32, 2, '2010-06-12 04:27:29'),
(1, 33, 3, '2010-06-12 04:27:29'),
(1, 34, 1, '2010-06-12 04:27:30'),
(1, 35, 2, '2010-06-12 04:27:30'),
(1, 36, 3, '2010-06-12 04:27:30');

-- --------------------------------------------------------

--
-- 表的结构 `icmphdr`
--

CREATE TABLE IF NOT EXISTS `icmphdr` (
  `sid` int(10) unsigned NOT NULL,
  `cid` int(10) unsigned NOT NULL,
  `icmp_type` tinyint(3) unsigned NOT NULL,
  `icmp_code` tinyint(3) unsigned NOT NULL,
  `icmp_csum` smallint(5) unsigned default NULL,
  `icmp_id` smallint(5) unsigned default NULL,
  `icmp_seq` smallint(5) unsigned default NULL,
  PRIMARY KEY  (`sid`,`cid`),
  KEY `icmp_type` (`icmp_type`)
) ENGINE=MyISAM DEFAULT CHARSET=latin1;

--
-- 导出表中的数据 `icmphdr`
--

INSERT INTO `icmphdr` (`sid`, `cid`, `icmp_type`, `icmp_code`, `icmp_csum`, `icmp_id`, `icmp_seq`) VALUES
(1, 1, 8, 0, 19791, 1, 12),
(1, 2, 8, 0, 19791, 1, 12),
(1, 3, 0, 0, 21839, 1, 12),
(1, 4, 8, 0, 19790, 1, 13),
(1, 5, 8, 0, 19790, 1, 13),
(1, 6, 0, 0, 21838, 1, 13),
(1, 7, 8, 0, 19789, 1, 14),
(1, 8, 8, 0, 19789, 1, 14),
(1, 9, 0, 0, 21837, 1, 14),
(1, 10, 8, 0, 19788, 1, 15),
(1, 11, 8, 0, 19788, 1, 15),
(1, 12, 0, 0, 21836, 1, 15),
(1, 13, 8, 0, 19802, 1, 1),
(1, 14, 8, 0, 19802, 1, 1),
(1, 15, 0, 0, 21850, 1, 1),
(1, 16, 8, 0, 19801, 1, 2),
(1, 17, 8, 0, 19801, 1, 2),
(1, 18, 0, 0, 21849, 1, 2),
(1, 19, 8, 0, 19800, 1, 3),
(1, 20, 8, 0, 19800, 1, 3),
(1, 21, 0, 0, 21848, 1, 3),
(1, 22, 8, 0, 19799, 1, 4),
(1, 23, 8, 0, 19799, 1, 4),
(1, 24, 0, 0, 21847, 1, 4),
(1, 25, 8, 0, 19802, 1, 1),
(1, 26, 8, 0, 19802, 1, 1),
(1, 27, 0, 0, 21850, 1, 1),
(1, 28, 8, 0, 19801, 1, 2),
(1, 29, 8, 0, 19801, 1, 2),
(1, 30, 0, 0, 21849, 1, 2),
(1, 31, 8, 0, 19800, 1, 3),
(1, 32, 8, 0, 19800, 1, 3),
(1, 33, 0, 0, 21848, 1, 3),
(1, 34, 8, 0, 19799, 1, 4),
(1, 35, 8, 0, 19799, 1, 4),
(1, 36, 0, 0, 21847, 1, 4);

-- --------------------------------------------------------

--
-- 表的结构 `iphdr`
--

CREATE TABLE IF NOT EXISTS `iphdr` (
  `sid` int(10) unsigned NOT NULL,
  `cid` int(10) unsigned NOT NULL,
  `ip_src` int(10) unsigned NOT NULL,
  `ip_dst` int(10) unsigned NOT NULL,
  `ip_ver` tinyint(3) unsigned default NULL,
  `ip_hlen` tinyint(3) unsigned default NULL,
  `ip_tos` tinyint(3) unsigned default NULL,
  `ip_len` smallint(5) unsigned default NULL,
  `ip_id` smallint(5) unsigned default NULL,
  `ip_flags` tinyint(3) unsigned default NULL,
  `ip_off` smallint(5) unsigned default NULL,
  `ip_ttl` tinyint(3) unsigned default NULL,
  `ip_proto` tinyint(3) unsigned NOT NULL,
  `ip_csum` smallint(5) unsigned default NULL,
  PRIMARY KEY  (`sid`,`cid`),
  KEY `ip_src` (`ip_src`),
  KEY `ip_dst` (`ip_dst`)
) ENGINE=MyISAM DEFAULT CHARSET=latin1;

--
-- 导出表中的数据 `iphdr`
--

INSERT INTO `iphdr` (`sid`, `cid`, `ip_src`, `ip_dst`, `ip_ver`, `ip_hlen`, `ip_tos`, `ip_len`, `ip_id`, `ip_flags`, `ip_off`, `ip_ttl`, `ip_proto`, `ip_csum`) VALUES
(1, 1, 3232249857, 3232249957, 4, 5, 0, 60, 19680, 0, 0, 64, 1, 15402),
(1, 2, 3232249857, 3232249957, 4, 5, 0, 60, 19680, 0, 0, 64, 1, 15402),
(1, 3, 3232249957, 3232249857, 4, 5, 0, 60, 274, 0, 0, 64, 1, 34808),
(1, 4, 3232249857, 3232249957, 4, 5, 0, 60, 19681, 0, 0, 64, 1, 15401),
(1, 5, 3232249857, 3232249957, 4, 5, 0, 60, 19681, 0, 0, 64, 1, 15401),
(1, 6, 3232249957, 3232249857, 4, 5, 0, 60, 275, 0, 0, 64, 1, 34807),
(1, 7, 3232249857, 3232249957, 4, 5, 0, 60, 19682, 0, 0, 64, 1, 15400),
(1, 8, 3232249857, 3232249957, 4, 5, 0, 60, 19682, 0, 0, 64, 1, 15400),
(1, 9, 3232249957, 3232249857, 4, 5, 0, 60, 276, 0, 0, 64, 1, 34806),
(1, 10, 3232249857, 3232249957, 4, 5, 0, 60, 19683, 0, 0, 64, 1, 15399),
(1, 11, 3232249857, 3232249957, 4, 5, 0, 60, 19683, 0, 0, 64, 1, 15399),
(1, 12, 3232249957, 3232249857, 4, 5, 0, 60, 277, 0, 0, 64, 1, 34805),
(1, 13, 3232249857, 3232249957, 4, 5, 0, 60, 13508, 0, 0, 64, 1, 21574),
(1, 14, 3232249857, 3232249957, 4, 5, 0, 60, 13508, 0, 0, 64, 1, 21574),
(1, 15, 3232249957, 3232249857, 4, 5, 0, 60, 4535, 0, 0, 64, 1, 30547),
(1, 16, 3232249857, 3232249957, 4, 5, 0, 60, 13509, 0, 0, 64, 1, 21573),
(1, 17, 3232249857, 3232249957, 4, 5, 0, 60, 13509, 0, 0, 64, 1, 21573),
(1, 18, 3232249957, 3232249857, 4, 5, 0, 60, 4536, 0, 0, 64, 1, 30546),
(1, 19, 3232249857, 3232249957, 4, 5, 0, 60, 13510, 0, 0, 64, 1, 21572),
(1, 20, 3232249857, 3232249957, 4, 5, 0, 60, 13510, 0, 0, 64, 1, 21572),
(1, 21, 3232249957, 3232249857, 4, 5, 0, 60, 4537, 0, 0, 64, 1, 30545),
(1, 22, 3232249857, 3232249957, 4, 5, 0, 60, 13515, 0, 0, 64, 1, 21567),
(1, 23, 3232249857, 3232249957, 4, 5, 0, 60, 13515, 0, 0, 64, 1, 21567),
(1, 24, 3232249957, 3232249857, 4, 5, 0, 60, 4538, 0, 0, 64, 1, 30544),
(1, 25, 3232249857, 3232249957, 4, 5, 0, 60, 5584, 0, 0, 64, 1, 29498),
(1, 26, 3232249857, 3232249957, 4, 5, 0, 60, 5584, 0, 0, 64, 1, 29498),
(1, 27, 3232249957, 3232249857, 4, 5, 0, 60, 60499, 0, 0, 64, 1, 40118),
(1, 28, 3232249857, 3232249957, 4, 5, 0, 60, 5585, 0, 0, 64, 1, 29497),
(1, 29, 3232249857, 3232249957, 4, 5, 0, 60, 5585, 0, 0, 64, 1, 29497),
(1, 30, 3232249957, 3232249857, 4, 5, 0, 60, 60500, 0, 0, 64, 1, 40117),
(1, 31, 3232249857, 3232249957, 4, 5, 0, 60, 5586, 0, 0, 64, 1, 29496),
(1, 32, 3232249857, 3232249957, 4, 5, 0, 60, 5586, 0, 0, 64, 1, 29496),
(1, 33, 3232249957, 3232249857, 4, 5, 0, 60, 60501, 0, 0, 64, 1, 40116),
(1, 34, 3232249857, 3232249957, 4, 5, 0, 60, 5593, 0, 0, 64, 1, 29489),
(1, 35, 3232249857, 3232249957, 4, 5, 0, 60, 5593, 0, 0, 64, 1, 29489),
(1, 36, 3232249957, 3232249857, 4, 5, 0, 60, 60502, 0, 0, 64, 1, 40115);

-- --------------------------------------------------------

--
-- 表的结构 `opt`
--

CREATE TABLE IF NOT EXISTS `opt` (
  `sid` int(10) unsigned NOT NULL,
  `cid` int(10) unsigned NOT NULL,
  `optid` int(10) unsigned NOT NULL,
  `opt_proto` tinyint(3) unsigned NOT NULL,
  `opt_code` tinyint(3) unsigned NOT NULL,
  `opt_len` smallint(6) default NULL,
  `opt_data` text,
  PRIMARY KEY  (`sid`,`cid`,`optid`)
) ENGINE=MyISAM DEFAULT CHARSET=latin1;

--
-- 导出表中的数据 `opt`
--


-- --------------------------------------------------------

--
-- 表的结构 `reference`
--

CREATE TABLE IF NOT EXISTS `reference` (
  `ref_id` int(10) unsigned NOT NULL auto_increment,
  `ref_system_id` int(10) unsigned NOT NULL,
  `ref_tag` text NOT NULL,
  PRIMARY KEY  (`ref_id`)
) ENGINE=MyISAM  DEFAULT CHARSET=latin1 AUTO_INCREMENT=2 ;

--
-- 导出表中的数据 `reference`
--

INSERT INTO `reference` (`ref_id`, `ref_system_id`, `ref_tag`) VALUES
(1, 1, '169');

-- --------------------------------------------------------

--
-- 表的结构 `reference_system`
--

CREATE TABLE IF NOT EXISTS `reference_system` (
  `ref_system_id` int(10) unsigned NOT NULL auto_increment,
  `ref_system_name` varchar(20) default NULL,
  PRIMARY KEY  (`ref_system_id`)
) ENGINE=MyISAM  DEFAULT CHARSET=latin1 AUTO_INCREMENT=2 ;

--
-- 导出表中的数据 `reference_system`
--

INSERT INTO `reference_system` (`ref_system_id`, `ref_system_name`) VALUES
(1, 'arachNIDS');

-- --------------------------------------------------------

--
-- 表的结构 `schema`
--

CREATE TABLE IF NOT EXISTS `schema` (
  `vseq` int(10) unsigned NOT NULL,
  `ctime` datetime NOT NULL,
  PRIMARY KEY  (`vseq`)
) ENGINE=MyISAM DEFAULT CHARSET=latin1;

--
-- 导出表中的数据 `schema`
--

INSERT INTO `schema` (`vseq`, `ctime`) VALUES
(107, '2010-06-10 08:23:17');

-- --------------------------------------------------------

--
-- 表的结构 `sensor`
--

CREATE TABLE IF NOT EXISTS `sensor` (
  `sid` int(10) unsigned NOT NULL auto_increment,
  `hostname` text,
  `interface` text,
  `filter` text,
  `detail` tinyint(4) default NULL,
  `encoding` tinyint(4) default NULL,
  `last_cid` int(10) unsigned NOT NULL,
  PRIMARY KEY  (`sid`)
) ENGINE=MyISAM  DEFAULT CHARSET=latin1 AUTO_INCREMENT=2 ;

--
-- 导出表中的数据 `sensor`
--

INSERT INTO `sensor` (`sid`, `hostname`, `interface`, `filter`, `detail`, `encoding`, `last_cid`) VALUES
(1, '192.168.56.101', 'eth0', NULL, 1, 0, 36);

-- --------------------------------------------------------

--
-- 表的结构 `signature`
--

CREATE TABLE IF NOT EXISTS `signature` (
  `sig_id` int(10) unsigned NOT NULL auto_increment,
  `sig_name` varchar(255) NOT NULL,
  `sig_class_id` int(10) unsigned NOT NULL,
  `sig_priority` int(10) unsigned default NULL,
  `sig_rev` int(10) unsigned default NULL,
  `sig_sid` int(10) unsigned default NULL,
  `sig_gid` int(10) unsigned default NULL,
  PRIMARY KEY  (`sig_id`),
  KEY `sign_idx` (`sig_name`(20)),
  KEY `sig_class_id_idx` (`sig_class_id`)
) ENGINE=MyISAM  DEFAULT CHARSET=latin1 AUTO_INCREMENT=4 ;

--
-- 导出表中的数据 `signature`
--

INSERT INTO `signature` (`sig_id`, `sig_name`, `sig_class_id`, `sig_priority`, `sig_rev`, `sig_sid`, `sig_gid`) VALUES
(1, 'ICMP PING Windows', 1, 3, 7, 382, 1),
(2, 'ICMP PING', 1, 3, 5, 384, 1),
(3, 'ICMP Echo Reply', 1, 3, 5, 408, 1);

-- --------------------------------------------------------

--
-- 表的结构 `sig_class`
--

CREATE TABLE IF NOT EXISTS `sig_class` (
  `sig_class_id` int(10) unsigned NOT NULL auto_increment,
  `sig_class_name` varchar(60) NOT NULL,
  PRIMARY KEY  (`sig_class_id`),
  KEY `sig_class_id` (`sig_class_id`),
  KEY `sig_class_name` (`sig_class_name`)
) ENGINE=MyISAM  DEFAULT CHARSET=latin1 AUTO_INCREMENT=2 ;

--
-- 导出表中的数据 `sig_class`
--

INSERT INTO `sig_class` (`sig_class_id`, `sig_class_name`) VALUES
(1, 'misc-activity');

-- --------------------------------------------------------

--
-- 表的结构 `sig_reference`
--

CREATE TABLE IF NOT EXISTS `sig_reference` (
  `sig_id` int(10) unsigned NOT NULL,
  `ref_seq` int(10) unsigned NOT NULL,
  `ref_id` int(10) unsigned NOT NULL,
  PRIMARY KEY  (`sig_id`,`ref_seq`)
) ENGINE=MyISAM DEFAULT CHARSET=latin1;

--
-- 导出表中的数据 `sig_reference`
--

INSERT INTO `sig_reference` (`sig_id`, `ref_seq`, `ref_id`) VALUES
(1, 1, 1);

-- --------------------------------------------------------

--
-- 表的结构 `tcphdr`
--

CREATE TABLE IF NOT EXISTS `tcphdr` (
  `sid` int(10) unsigned NOT NULL,
  `cid` int(10) unsigned NOT NULL,
  `tcp_sport` smallint(5) unsigned NOT NULL,
  `tcp_dport` smallint(5) unsigned NOT NULL,
  `tcp_seq` int(10) unsigned default NULL,
  `tcp_ack` int(10) unsigned default NULL,
  `tcp_off` tinyint(3) unsigned default NULL,
  `tcp_res` tinyint(3) unsigned default NULL,
  `tcp_flags` tinyint(3) unsigned NOT NULL,
  `tcp_win` smallint(5) unsigned default NULL,
  `tcp_csum` smallint(5) unsigned default NULL,
  `tcp_urp` smallint(5) unsigned default NULL,
  PRIMARY KEY  (`sid`,`cid`),
  KEY `tcp_sport` (`tcp_sport`),
  KEY `tcp_dport` (`tcp_dport`),
  KEY `tcp_flags` (`tcp_flags`)
) ENGINE=MyISAM DEFAULT CHARSET=latin1;

--
-- 导出表中的数据 `tcphdr`
--


-- --------------------------------------------------------

--
-- 表的结构 `udphdr`
--

CREATE TABLE IF NOT EXISTS `udphdr` (
  `sid` int(10) unsigned NOT NULL,
  `cid` int(10) unsigned NOT NULL,
  `udp_sport` smallint(5) unsigned NOT NULL,
  `udp_dport` smallint(5) unsigned NOT NULL,
  `udp_len` smallint(5) unsigned default NULL,
  `udp_csum` smallint(5) unsigned default NULL,
  PRIMARY KEY  (`sid`,`cid`),
  KEY `udp_sport` (`udp_sport`),
  KEY `udp_dport` (`udp_dport`)
) ENGINE=MyISAM DEFAULT CHARSET=latin1;

--
-- 导出表中的数据 `udphdr`
--

