package dynamodb

import (
	"fmt"
	"reflect"
	"sync"

	"aws-in-a-box/arn"
	"aws-in-a-box/awserrors"
)

type Table struct {
	Name                 string
	ARN                  string
	BillingMode          string
	AttributeDefinitions []APIAttributeDefinition
	KeySchema            []APIKeySchemaElement

	PrimaryKeyAttributeName string
	ItemsByPrimaryKey       map[string][]APIItem
	ItemCount               int
}

func (t *Table) toAPI() APITableDescription {
	return APITableDescription{
		AttributeDefinitions: t.AttributeDefinitions,
		ItemCount:            t.ItemCount,
		KeySchema:            t.KeySchema,
		// TODO: delayed creation
		TableARN:    t.ARN,
		TableStatus: "ACTIVE",
	}
}

type DynamoDB struct {
	arnGenerator arn.Generator

	mu           sync.Mutex
	tablesByName map[string]*Table
}

func New(generator arn.Generator) *DynamoDB {
	d := &DynamoDB{
		arnGenerator: generator,
		tablesByName: make(map[string]*Table),
	}
	return d
}

// https://docs.aws.amazon.com/amazondynamodb/latest/APIReference/API_CreateTable.html
func (d *DynamoDB) CreateTable(input CreateTableInput) (*CreateTableOutput, *awserrors.Error) {
	d.mu.Lock()
	defer d.mu.Unlock()

	if _, ok := d.tablesByName[input.TableName]; ok {
		return nil, awserrors.ResourceInUseException("Table already exists")
	}

	primaryKeyAttributeName := ""
	for _, keySchemaElement := range input.KeySchema {
		if keySchemaElement.KeyType == "HASH" {
			primaryKeyAttributeName = keySchemaElement.AttributeName
			break
		}
	}
	if primaryKeyAttributeName == "" {
		return nil, awserrors.InvalidArgumentException("KeySchema must have a HASH key")
	}

	t := &Table{
		Name:                    input.TableName,
		ARN:                     d.arnGenerator.Generate("dynamodb", "table", input.TableName),
		BillingMode:             input.BillingMode,
		AttributeDefinitions:    input.AttributeDefinitions,
		KeySchema:               input.KeySchema,
		PrimaryKeyAttributeName: primaryKeyAttributeName,
		ItemsByPrimaryKey:       make(map[string][]APIItem),
	}
	d.tablesByName[input.TableName] = t

	fmt.Println("CreateTable", input)
	return &CreateTableOutput{
		TableDescription: t.toAPI(),
	}, nil
}

// https://docs.aws.amazon.com/amazondynamodb/latest/APIReference/API_CreateTable.html
func (d *DynamoDB) DescribeTable(input DescribeTableInput) (*DescribeTableOutput, *awserrors.Error) {
	d.mu.Lock()
	defer d.mu.Unlock()

	t, ok := d.tablesByName[input.TableName]
	if !ok {
		return nil, awserrors.InvalidArgumentException("Table does not exist")
	}

	return &DescribeTableOutput{
		Table: t.toAPI(),
	}, nil
}

// https://docs.aws.amazon.com/amazondynamodb/latest/APIReference/API_Scan.html
func (d *DynamoDB) Scan(input ScanInput) (*ScanOutput, *awserrors.Error) {
	d.mu.Lock()
	defer d.mu.Unlock()

	/*data, _ := json.MarshalIndent(input, "", "  ")
	fmt.Println("Scan", string(data))*/

	t, ok := d.tablesByName[input.TableName]
	if !ok {
		return nil, awserrors.InvalidArgumentException("Table does not exist")
	}

	var allItems []APIItem
	for _, items := range t.ItemsByPrimaryKey {
		allItems = append(allItems, items...)
	}

	return &ScanOutput{
		Count: len(allItems),
		Items: allItems,
	}, nil
}

// https://docs.aws.amazon.com/amazondynamodb/latest/APIReference/API_PutItem.html
func (d *DynamoDB) PutItem(input PutItemInput) (*PutItemOutput, *awserrors.Error) {
	d.mu.Lock()
	defer d.mu.Unlock()

	/*data, _ := json.MarshalIndent(input, "", "  ")
	fmt.Println("PutItem", string(data))*/

	t, ok := d.tablesByName[input.TableName]
	if !ok {
		return nil, awserrors.InvalidArgumentException("Table does not exist")
	}
	key := input.Item[t.PrimaryKeyAttributeName].S
	if key == "" {
		return nil, awserrors.InvalidArgumentException("PrimaryKey must be provided (and string)")
	}
	t.ItemsByPrimaryKey[key] = append(t.ItemsByPrimaryKey[key], input.Item)
	t.ItemCount += 1

	return &PutItemOutput{}, nil
}

// https://docs.aws.amazon.com/amazondynamodb/latest/APIReference/API_UpdateItem.html
func (d *DynamoDB) UpdateItem(input UpdateItemInput) (*UpdateItemOutput, *awserrors.Error) {
	d.mu.Lock()
	defer d.mu.Unlock()

	/*data, _ := json.MarshalIndent(input, "", "  ")
	fmt.Println("UpdateItem", string(data))*/

	t, ok := d.tablesByName[input.TableName]
	if !ok {
		return nil, awserrors.InvalidArgumentException("Table does not exist")
	}

	// TODO: composite keys
	key := input.Key[t.PrimaryKeyAttributeName].S
	if key == "" {
		return nil, awserrors.InvalidArgumentException("PrimaryKey must be provided (and string)")
	}
	items := t.ItemsByPrimaryKey[key]

	itemCountIncrease := 0
	var existingItem map[string]APIAttributeValue
	if len(items) == 0 {
		existingItem = make(map[string]APIAttributeValue)
		itemCountIncrease = 1
	} else if len(items) == 1 {
		existingItem = items[0]
		t.ItemsByPrimaryKey[key] = items[:0]
	} else {
		return nil, awserrors.XXX_TODO("Multiple items with same primary key")
	}

	// Check preconditions
	for attribute, expectation := range input.Expected {
		attr, exists := existingItem[attribute]
		if expectation.Exists != nil {
			if *expectation.Exists != exists {
				return nil, awserrors.XXX_TODO("Attribute exists mismatch")
			}
		}
		switch expectation.ComparisonOperator {
		case "":
		case "EQ":
			if !reflect.DeepEqual(attr, expectation.Value) {
				return nil, awserrors.XXX_TODO("Attribute EQ mismatch")
			}
		case "NEQ":
			if reflect.DeepEqual(attr, expectation.Value) {
				return nil, awserrors.XXX_TODO("Attribute NEQ mismatch")
			}
		default:
			return nil, awserrors.InvalidArgumentException("Invalid expectation comparison operator: " + expectation.ComparisonOperator)
		}
	}

	// Perform update
	for attribute, update := range input.AttributeUpdates {
		switch update.Action {
		case "PUT":
			existingItem[attribute] = update.Value
		case "DELETE":
			delete(existingItem, attribute)
		case "ADD":
			// TODO
			// fallthrough
		default:
			return nil, awserrors.InvalidArgumentException("Invalid update action: " + update.Action)
		}
	}

	t.ItemCount += itemCountIncrease
	t.ItemsByPrimaryKey[key] = []APIItem{existingItem}
	return &UpdateItemOutput{}, nil
}
