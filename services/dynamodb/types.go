package dynamodb

type CreateTableInput struct {
	AttributeDefinitions []APIAttributeDefinition
	TableName            string
	BillingMode          string
	KeySchema            []APIKeySchemaElement
}

type CreateTableOutput struct {
	TableDescription APITableDescription
}

type APITableDescription struct {
	AttributeDefinitions []APIAttributeDefinition
	ItemCount            int
	KeySchema            []APIKeySchemaElement
	TableARN             string
	TableStatus          string
}

type APIAttributeType string

const (
	AttributeType_String  = APIAttributeType("S")
	AttributeType_Binary  = APIAttributeType("B")
	AttributeType_Numeric = APIAttributeType("N")
)

type APIAttributeDefinition struct {
	AttributeName string
	AttributeType APIAttributeType
}

type APIKeySchemaElement struct {
	AttributeName string
	KeyType       string
}

type DescribeTableInput struct {
	TableName string
}

type DescribeTableOutput struct {
	Table APITableDescription
}

type ScanInput struct {
	FilterExpression     string
	Limit                int
	ProjectionExpression string
	Select               string
	TableName            string
}

type ScanOutput struct {
	Count        int
	Items        []APIItem
	ScannedCount int
}

type APIAttributeValue struct {
	B    string // base64 encoded binary
	BOOL bool
	BS   []string                     // base64 encoded binary set
	L    []APIAttributeValue          // list
	M    map[string]APIAttributeValue // map
	N    string                       // number
	NS   []string                     // number set
	NULL bool                         // null
	S    string                       // string
	SS   []string                     // string set
}

type GetItemInput struct {
	AttributesToGet          []string
	ConsistentRead           bool
	ExpressionAttributeNames map[string]string
	Key                      map[string]APIAttributeValue
	ProjectionExpression     string
	TableName                string
}

type GetItemOutput struct {
	Item APIItem
}

type PutItemReturnValues string

const (
	PutItems_NONE    = PutItemReturnValues("NONE")
	PutItems_ALL_OLD = PutItemReturnValues("ALL_OLD")
)

type PutItemInput struct {
	Expected map[string]struct {
		AttributeValueList []APIAttributeValue
		ComparisonOperator string
		Exists             bool
		Value              APIAttributeValue
	}
	Item         APIItem
	TableName    string
	ReturnValues PutItemReturnValues
}

type APIItem map[string]APIAttributeValue

type PutItemOutput struct {
	Attributes APIItem
}

type UpdateItemReturnValues string

const (
	UpdateItems_NONE        = UpdateItemReturnValues("NONE")
	UpdateItems_ALL_OLD     = UpdateItemReturnValues("ALL_OLD")
	UpdateItems_UPDATED_OLD = UpdateItemReturnValues("UPDATED_OLD")
	UpdateItems_ALL_NEW     = UpdateItemReturnValues("ALL_NEW")
	UpdateItems_UPDATED_NEW = UpdateItemReturnValues("UPDATED_NEW")
)

type UpdateItemInput struct {
	AttributeUpdates map[string]struct {
		Action string
		Value  APIAttributeValue
	}
	Expected map[string]struct {
		AttributeValueList []APIAttributeValue
		ComparisonOperator string
		Exists             *bool // Support explicit false
		Value              APIAttributeValue
	}
	Key          map[string]APIAttributeValue
	ReturnValues UpdateItemReturnValues
	TableName    string
}

type UpdateItemOutput struct {
	Attributes APIItem
}
