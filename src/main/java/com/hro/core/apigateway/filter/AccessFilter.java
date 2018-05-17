package com.hro.core.apigateway.filter;

import com.hro.core.apigateway.utils.RsaUtil;
import com.netflix.zuul.ZuulFilter;
import com.netflix.zuul.context.RequestContext;
import org.apache.commons.lang.StringUtils;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import javax.servlet.http.HttpServletRequest;
import java.util.Base64;

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
    public Object run() {
        RequestContext ctx = RequestContext.getCurrentContext();
        HttpServletRequest request = ctx.getRequest();
        // 通过appid和accessToken来检验服务的权限
        String appIdStr = request.getHeader("appId");
        int appId = StringUtils.isEmpty(appIdStr)?0:Integer.parseInt(appIdStr);
        String accessToken = request.getHeader("accessToken");

        if(accessToken == null) {
            logger.info("权限校验失败，appId={}, accessToken={}", new Object[]{appId, accessToken});
            ctx.setSendZuulResponse(false);
            ctx.setResponseStatusCode(401);
            return null;
        }
        // 用RSA私钥进行token解密
        String decryDatas = new String(RsaUtil.decryptData(Base64.getDecoder().decode(accessToken)));
        boolean isAccessed = false;
        switch (appId) {
            case 1001: isAccessed = "Cposition_Auth_Key".equals(decryDatas);
                break;
            case 1002: isAccessed = "Cmanager_Auth_key".equals(decryDatas);
                break;
        }

        if(!isAccessed) {
            ctx.setSendZuulResponse(false);
            ctx.setResponseStatusCode(401);
        }

        logger.info("权限校验成功，appId={}, accessToken={}", new Object[]{appId, accessToken});
        return null;
    }
}
