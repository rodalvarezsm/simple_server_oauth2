package controller

type Oauth2Controller struct {
	service service.EndpointConfigServiceInterface
	engine  *gin.Engine
	logger  *zap.Logger
}

func NewOauth2Controller(e *gin.Engine, s service.EndpointConfigServiceInterface, l *zap.Logger) {
	endpointConfigCtrl := &EndpointConfigController{
		service: s,
		engine:  e,
		logger:  l,
	}
	endpointConfigCtrl.setUpRoutes()
}
