-- phpMyAdmin SQL Dump
-- version 3.3.1
-- http://www.phpmyadmin.net
--
-- 主机: localhost
-- 生成日期: 2010 年 06 月 11 日 11:03
-- 服务器版本: 5.0.22
-- PHP 版本: 5.2.13

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
-- 表的结构 `ag_ip_history`
--

CREATE TABLE IF NOT EXISTS `ag_ip_history` (
  `user_id` int(10) NOT NULL,
  `date` datetime NOT NULL,
  `state` int(3) NOT NULL,
  `ip` char(15) NOT NULL,
  PRIMARY KEY  (`user_id`,`date`,`state`)
) ENGINE=MyISAM DEFAULT CHARSET=gb2312;

--
-- 转存表中的数据 `ag_ip_history`
--

INSERT INTO `ag_ip_history` (`user_id`, `date`, `state`, `ip`) VALUES
(1, '2010-06-03 14:43:26', 2, '127.0.0.1'),
(1, '2010-06-03 14:43:54', 2, '127.0.0.1'),
(1, '2010-06-03 14:51:38', 2, '127.0.0.1'),
(2, '2010-06-03 15:36:22', 2, '127.0.0.1'),
(1, '2010-06-03 15:37:46', 2, '127.0.0.1'),
(1, '2010-06-03 16:57:04', 2, '127.0.0.1'),
(1, '2010-06-04 09:18:05', 2, '127.0.0.1'),
(1, '2010-06-04 19:05:08', 2, '127.0.0.1'),
(1, '2010-06-05 13:46:13', 2, '127.0.0.1'),
(1, '2010-06-06 14:13:09', 2, '127.0.0.1'),
(1, '2010-06-06 14:55:38', 2, '192.168.149.1'),
(2, '2010-06-06 15:36:11', 1, '192.168.149.1'),
(1, '2010-06-06 15:38:37', 2, '192.168.149.1'),
(1, '2010-06-06 16:38:28', 2, '192.168.149.1'),
(1, '2010-06-07 09:56:55', 2, '192.168.149.1'),
(1, '2010-06-07 21:12:32', 2, '192.168.149.1'),
(1, '2010-06-09 23:35:28', 2, '192.168.149.1'),
(1, '2010-06-10 08:52:39', 2, '192.168.149.1'),
(1, '2010-06-11 09:38:02', 2, '192.168.149.1');
