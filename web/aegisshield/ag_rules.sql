-- phpMyAdmin SQL Dump
-- version 3.3.1
-- http://www.phpmyadmin.net
--
-- 主机: localhost
-- 生成日期: 2010 年 06 月 11 日 20:49
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
-- 表的结构 `ag_rules`
--

CREATE TABLE IF NOT EXISTS `ag_rules` (
  `id` int(10) NOT NULL,
  `type` int(11) NOT NULL,
  `rule` mediumtext NOT NULL,
  `proto` int(11) NOT NULL,
  PRIMARY KEY  (`id`)
) ENGINE=MyISAM DEFAULT CHARSET=gb2312;

--
-- 转存表中的数据 `IPT_rules`
--

INSERT INTO `ag_rules` (`id`, `type`, `rule`, `proto`) VALUES
(2, 2, '413524363465', 2);
