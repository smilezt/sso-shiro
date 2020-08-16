package com.test.shiro.realm;

import org.apache.shiro.authc.AuthenticationException;
import org.apache.shiro.authc.AuthenticationInfo;
import org.apache.shiro.authc.AuthenticationToken;
import org.apache.shiro.authc.SimpleAuthenticationInfo;
import org.apache.shiro.authz.AuthorizationInfo;
import org.apache.shiro.cas.CasRealm;
import org.apache.shiro.cas.CasToken;
import org.apache.shiro.subject.PrincipalCollection;
import org.apache.shiro.subject.SimplePrincipalCollection;
import org.apache.shiro.util.CollectionUtils;
import org.apache.shiro.util.StringUtils;
import org.jasig.cas.client.authentication.AttributePrincipal;
import org.jasig.cas.client.validation.Assertion;
import org.jasig.cas.client.validation.TicketValidationException;
import org.jasig.cas.client.validation.TicketValidator;

import java.util.List;

public class ShiroCasRealm extends CasRealm {

    /**
     * 用户身份认证
     */
    @Override
    protected AuthenticationInfo doGetAuthenticationInfo(AuthenticationToken token) throws AuthenticationException {
        // 此时接收的AuthenticationToken对象实际上是CasToken类型
        CasToken casToken = (CasToken) token;  // 现在需要返回的是CAS认证标记
        if (casToken == null) {   // 如果现在没有返回token标记
            return null;  // 当前的登录失败
        }

        // CAS一定要返回给用户一个票根，所以需要取得这个票根的内容
        String ticket = (String) casToken.getCredentials();
        // 需要对票根的有效性进行验证
        if (!StringUtils.hasText(ticket)) {  // 票根验证失败
            return null;  // 当前的登录失败
        }

        // 如果现在票根验证的格式正确，那么需要进行票根的有效性验证
        TicketValidator ticketValidator = super.ensureTicketValidator();

        try {
            // 首先需要针对于票根的CAS做一个验证处理
            Assertion casAssertion = ticketValidator.validate(ticket, super.getCasService());
            // 当验证处理完成之后，应该通过CAS取得用户信息
            AttributePrincipal casPrincipal = casAssertion.getPrincipal();
            String mid = casPrincipal.getName();  // 取出当前登录的用户名
            // 取出用户名之后需要将所有的相关信息（包括CAS相关信息）一起进行一个列表的创建
            List principals = CollectionUtils.asList(mid, casPrincipal.getAttributes());
            PrincipalCollection principalCollection = new SimplePrincipalCollection(principals,super.getName());
            return new SimpleAuthenticationInfo(principalCollection, ticket);
        } catch (TicketValidationException e) {
            e.printStackTrace();
        }
        return super.doGetAuthenticationInfo(token);
    }

    /**
     * 用户授权
     */
    @Override
    protected AuthorizationInfo doGetAuthorizationInfo(PrincipalCollection principals) {
        // 没有权限验证体系，所以直接返回
        return super.doGetAuthorizationInfo(principals);
    }
}
