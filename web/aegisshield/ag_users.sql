-- phpMyAdmin SQL Dump
-- version 3.3.1
-- http://www.phpmyadmin.net
--
-- 主机: localhost
-- 生成日期: 2010 年 06 月 11 日 11:01
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
-- 表的结构 `ag_users`
--

CREATE TABLE IF NOT EXISTS `ag_users` (
  `id` int(10) NOT NULL auto_increment,
  `username` varchar(20) NOT NULL,
  `passwd` varchar(100) NOT NULL,
  `privilege` int(1) default NULL,
  `name` varchar(60) default NULL,
  `surname` varchar(60) default NULL,
  `phone` varchar(30) default NULL,
  `fax` varchar(30) default NULL,
  `mobile_phone` varchar(30) default NULL,
  `email` varchar(100) NOT NULL,
  `language` varchar(255) NOT NULL,
  `city` varchar(255) default NULL,
  `nation` varchar(255) default NULL,
  `place` varchar(255) default NULL,
  `zip_code` varchar(255) default NULL,
  `address` varchar(255) default NULL,
  `group_id` int(10) NOT NULL,
  `account` int(1) default NULL,
  `created` datetime default NULL,
  PRIMARY KEY  (`id`)
) ENGINE=MyISAM DEFAULT CHARSET=gb2312 AUTO_INCREMENT=3 ;

--
-- 转存表中的数据 `ag_users`
--

INSERT INTO `ag_users` (`id`, `username`, `passwd`, `privilege`, `name`, `surname`, `phone`, `fax`, `mobile_phone`, `email`, `language`, `city`, `nation`, `place`, `zip_code`, `address`, `group_id`, `account`, `created`) VALUES
(1, 'admin', '0192023a7bbd73250516f069df18b500', 2, 'Zhong', 'Cunwei', '', '', '', 'zhongcunwei@gmail.com', 'en', '', '', '', '', '', 1, 1, '2010-06-03 14:14:47'),
(2, 'zhangwei', 'ecb24e39c8d0dd94d81d6b1c5f06477d', 1, 'Zhang', 'wei', '', '', '', 'zhangwei@qq.com', 'en', '', '', '', '', '', 1, 1, '2010-06-03 15:35:41');
