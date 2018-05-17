package com.hro.core.apigateway.utils;

import java.util.UUID;

/**
 * 字符串工具类
 * @author Mojianzhang
 * 2017年9月5日
 */
public class StringUtils extends org.apache.commons.lang3.StringUtils{
	
	/**
	 * 把对象转换为字符串
	 * @param obj
	 * @return
	 */
	public static String toString(Object obj){
		if( obj == null ){
			return "";
		}
		return String.valueOf(obj);
	}
	
	/**
	 * 把对象转换为字符串,且去掉前后空格
	 * @param obj
	 * @return
	 */
	public static String toTrim(Object obj){
		if( obj == null || "".equals(String.valueOf(obj)) ){
			return "";
		}
		return String.valueOf(obj).trim();
	}
	
	/**
	 * 生成UUID
	 * @return
	 */
	public static String getUuid(){
		String uuid = UUID.randomUUID().toString();
		return uuid;
	}
}
