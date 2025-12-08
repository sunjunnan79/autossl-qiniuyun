package email

import (
	"crypto/tls"
	"fmt"
	"github.com/jordan-wright/email"
	"net/smtp"
	"net/textproto"
)

// EmailClient 结构体
type EmailClient struct {
	SMTPHost string // SMTP 服务器地址
	SMTPPort string // SMTP 端口（25、465（SSL）、587（TLS））
	SMTPUser string // 邮箱用户名
	SMTPPass string // 邮箱密码
	Sender   string // 发件人昵称
}

// NewEmailClient 创建邮件客户端
func NewEmailClient(
	userName,
	password,
	sender,
	smtpHost,
	smtpPort string) *EmailClient {
	return &EmailClient{
		SMTPHost: smtpHost,
		SMTPPort: smtpPort,
		SMTPUser: userName,
		SMTPPass: password,
		Sender:   sender,
	}
}

// SendEmail 发送邮件
func (c *EmailClient) SendEmail(to []string, subject, text, html string, attachments []string) error {
	e := &email.Email{
		To:      to,
		From:    fmt.Sprintf("%s <%s>", c.Sender, c.SMTPUser),
		Subject: subject,
		HTML:    []byte(html),
		Headers: textproto.MIMEHeader{},
		Text:    []byte(text),
	}
	for _, attachmentPath := range attachments {
		// 如果文件不存在或无法读取，AttachFile 将返回错误
		_, err := e.AttachFile(attachmentPath)
		if err != nil {
			// 注意：如果一个附件失败，通常应该返回错误并停止发送
			return fmt.Errorf("failed to attach file %s: %w", attachmentPath, err)
		}
	}
	err := e.SendWithTLS(c.SMTPHost+":"+c.SMTPPort, smtp.PlainAuth("", c.SMTPUser, c.SMTPPass, c.SMTPHost), &tls.Config{ServerName: c.SMTPHost})
	if err != nil {
		return err
	}

	return nil
}
