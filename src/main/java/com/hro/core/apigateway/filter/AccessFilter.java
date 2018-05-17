package com.hro.core.apigateway.filter;

import com.netflix.zuul.ZuulFilter;
import com.netflix.zuul.context.RequestContext;
import com.netflix.zuul.exception.ZuulException;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import javax.servlet.http.HttpServletRequest;

public class AccessFilter extends ZuulFilter {

    private Logger logger = LoggerFactory.getLogger(AccessFilter.class);

    @Override
    public String filterType() {
        return "pre";
    }

    @Override
    public int filterOrder() {
        return 0;
    }

    @Override
    public boolean shouldFilter() {
        return true;
    }

    @Override
    public Object run() throws ZuulException {
        RequestContext ctx = RequestContext.getCurrentContext();
        HttpServletRequest request = ctx.getRequest();
        // 通过appid和accessToken来检验服务的权限
        String appId = request.getHeader("appId");
        String accessToken = request.getHeader("accessToken");

        if(accessToken == null) {
            //TODO 用RSA私钥进行解密
            logger.info("权限校验失败，appId={}, accessToken={}", new Object[]{appId, accessToken});
            ctx.setSendZuulResponse(false);
            ctx.setResponseStatusCode(401);
            return null;
        }
        logger.info("权限校验成功，appId={}, accessToken={}", new Object[]{appId, accessToken});
        return null;
    }
}
