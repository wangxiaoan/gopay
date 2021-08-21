package alipay

import (
	"github.com/go-pay/gopay"
	"github.com/go-pay/gopay/alipay"
	"github.com/go-pay/gopay/pkg/xlog"
)

func OpenAuthTokenApp() {
	privateKey := "MIIEogIBAAKCAQEAy+CRzKw4krA2RzCDTqg5KJg92XkOY0RN3pW4sYInPqnGtHV7YDHu5nMuxY6un+dLfo91OFOEg+RI+WTOPoM4xJtsOaJwQ1lpjycoeLq1OyetGW5Q8wO+iLWJASaMQM/t/aXR/JHaguycJyqlHSlxANvKKs/tOHx9AhW3LqumaCwz71CDF/+70scYuZG/7wxSjmrbRBswxd1Sz9KHdcdjqT8pmieyPqnM24EKBexHDmQ0ySXvLJJy6eu1dJsPIz+ivX6HEfDXmSmJ71AZVqZyCI1MhK813R5E7XCv5NOtskTe3y8uiIhgGpZSdB77DOyPLcmVayzFVLAQ3AOBDmsY6wIDAQABAoIBAHjsNq31zAw9FcR9orQJlPVd7vlJEt6Pybvmg8hNESfanO+16rpwg2kOEkS8zxgqoJ1tSzJgXu23fgzl3Go5fHcoVDWPAhUAOFre9+M7onh2nPXDd6Hbq6v8OEmFapSaf2b9biHnBHq5Chk08v/r74l501w3PVVOiPqulJrK1oVb+0/YmCvVFpGatBcNaefKUEcA+vekWPL7Yl46k6XeUvRfTwomCD6jpYLUhsAKqZiQJhMGoaLglZvkokQMF/4G78K7FbbVLMM1+JDh8zJ/DDVdY2vHREUcCGhl4mCVQtkzIbpxG++vFg7/g/fDI+PquG22hFILTDdtt2g2fV/4wmkCgYEA6goRQYSiM03y8Tt/M4u1Mm7OWYCksqAsU7rzQllHekIN3WjD41Xrjv6uklsX3sTG1syo7Jr9PGE1xQgjDEIyO8h/3lDQyLyycYnyUPGNNMX8ZjmGwcM51DQ/QfIrY/CXjnnW+MVpmNclAva3L33KXCWjw20VsROV1EA8LCL94BUCgYEA3wH4ANpzo7NqXf+2WlPPMuyRrF0QPIRGlFBNtaKFy0mvoclkREPmK7+N4NIGtMf5JNODS5HkFRgmU4YNdupA2I8lIYpD+TsIobZxGUKUkYzRZYZ1m1ttL69YYvCVz9Xosw/VoQ+RrW0scS5yUKqFMIUOV2R/Imi//c5TdKx6VP8CgYAnJ1ADugC4vI2sNdvt7618pnT3HEJxb8J6r4gKzYzbszlGlURQQAuMfKcP7RVtO1ZYkRyhmLxM4aZxNA9I+boVrlFWDAchzg+8VuunBwIslgLHx0/4EoUWLzd1/OGtco6oU1HXhI9J9pRGjqfO1iiIifN/ujwqx7AFNknayG/YkQKBgD6yNgA/ak12rovYzXKdp14Axn+39k2dPp6J6R8MnyLlB3yruwW6NSbNhtzTD1GZ+wCQepQvYvlPPc8zm+t3tl1r+Rtx3ORf5XBZc3iPkGdPOLubTssrrAnA+U9vph61W+OjqwLJ9sHUNK9pSHhHSIS4k6ycM2YAHyIC9NGTgB0PAoGAJjwd1DgMaQldtWnuXjvohPOo8cQudxXYcs6zVRbx6vtjKe2v7e+eK1SSVrR5qFV9AqxDfGwq8THenRa0LC3vNNplqostuehLhkWCKE7Y75vXMR7N6KU1kdoVWgN4BhXSwuRxmHMQfSY7q3HG3rDGz7mzXo1FVMr/uE4iDGm0IXY="
	//privateKey := "MIIEowIBAAKCAQEAu8U3O5C6g1KRyZySX1NiVbakSk6+rE5GBt7xEPsRXEtaRsL3YQQOC95+0pGaLTvGTkzZ2sfSZ6mvl9ryYQ1uBAAqSoGWm24djxpwm7JJrkbOsTiKCmB4JnI5xIvvoLZApwtC4USlNSytxXMoxSrTc6lo41ev0ENnh4+dhL9iokLH35uGjHyVi8ovCpo940X8BIlmta3WBGmLIU3s5xGwUwqRHFlWySxaCuEuhhQsodAoqWV9HpM549uVXZCiqkUDugUnfIaUM7vlgMgNa0ol81a7GdQnqmqyg7XMH81chPWWrUQCo5E7oXWXFwSMraNwZbw4qBZYMGLGuKqNqbscqwIDAQABAoIBAC9f38KYjmZJs9yxM0D30cycazEQUw04JnTfVOUa41Ns85b849tHYZ/fABJyh/q3pR3mR+TqG4zqBBKFPDf+Ym6B+CmaLnyCuNR9MEIoJmzhEo8mG7Xohwf0M90CDXB36zH6JmKdpi0XW7SAjJ3KY1VAPeV2Hzalev553p06iFE1pp4wtvF/XFeensGQG58tBCDuzhzxNMZfDqOJPx35Q5HIuW5CS1JdclY7SZol7i5HtgaSkjVQ/3wKRZCK4nTOoQW5uh4ogdI4KKDX7cFmQESxMNsCo+A9oQYOoD7yw9wsCkENlPyUDbAcFNFTDWpOAVXn/M0jQWQDzaT7GlhrqlkCgYEA+QFTewivhL+nmbcTrgscyzFNeoeBOct9MH8YJNWIblKT35Lg0HT1UAW9Jey46d6al+Xz/0sM0c+3nbYb9Va2oPahW70hmbTchBrqKAh/svb9yCeWw5i6NuzUNRZ5kz5ufr42XRRVNR2IJ2Av4RGfVA7W/uhAnIZBPngk5CoyfgcCgYEAwQuH9DH46fvKTB+B1kDngpKQw9Jn2ZXVz8dyYnhdH/SZgohwD/jTldx9ck42bFw4+3qHI6DJSxBxqeuaGQqmD5Y3YStP3Gb33EABACpLt1NV4AId8rWfrizJTxy5+PJONHNmDNL0Fyv53qtsG1rv+Unye6Pfeo6pkKmK49u/Az0CgYEAtR3Oz934dNFGohs1GFIC5pT86xPm3dfyPjUjpZ8ftkcgQe2+0kFQMZ2LACvYMFv3DGd5e4bmUzIIN5G/cktZWWkq4uSFrRyNjRVanjXYVJ8s5spM8gaD4/GNRPQNCBnQGyZVuoxQkeriHunqyYWc43JL1Wuvm2pXyI1xH/jFcz8CgYB1IN34mGmC7rcrwOIycWcGno8fgYZpSrRUQZtxi75VKUALJ2V3C261uvaSaEo1LS+Vxh5Ay8nWtb+BbeYt03w2cNphJrpp7D/vbxYsV31hWjr8k8w/+1tLfvkV+0QLfFlfEbWVill3xcLyC+ioIGECTI/H3QI3hl/z2irfXfFjsQKBgA+vBD22XWD1drUccPA0mMJdVMW/yrd3HVbHLVHaNqkdPFUAN8k27icXxdE2gKoHWmDeW0SZ5Wm7Hc+79f222ZS401vzlL78sIXBydYlsxn3zDowt5U9WTDPVxoqx+aStUriDPiV3fnxj9D/Q4IAEYlqI1gjRBF1o15zRFQZAkJv"
	//初始化支付宝客户端
	//    appId：应用ID
	//    privateKey：应用私钥，支持PKCS1和PKCS8
	//    isProd：是否是正式环境
	client, err := alipay.NewClient("2016091200494382", privateKey, false)
	if err != nil {
		xlog.Error(err)
		return
	}
	//配置公共参数
	client.SetCharset("utf-8").
		SetSignType(alipay.RSA2)

	//请求参数
	bm := make(gopay.BodyMap).
		Set("grant_type", "authorization_code").
		Set("code", "866185490c4e40efa9f71efea6766X02")
	//发起请求
	aliRsp, err := client.OpenAuthTokenApp(bm)
	if err != nil {
		xlog.Error("err:", err)
		return
	}
	xlog.Debug("aliRsp:", *aliRsp)
}
